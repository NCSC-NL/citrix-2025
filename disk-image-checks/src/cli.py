# /// script
# requires-python = ">=3.11,<3.13"
# dependencies = [
#   "dissect",
#   "tabulate",
#   "yara-python",
#   "pyyaml",
# ]
# ///
from datetime import datetime
import json
import os
from flow.record import RecordDescriptor
from dissect.target import Target

import argparse
import yaml
import sys
import logging
from tabulate import tabulate
from pathlib import Path
from checker.models import ALL_CHECKS, ChecksConfig, ValidCheckType
import checker.checks as check_functions

SCRIPT_VERSION = "1.0"
HELP_URL = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"

logging.basicConfig(
    level=logging.ERROR,
    format="[%(filename)s %(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)


logger = logging.getLogger("iocitrix")
logger.setLevel(logging.DEBUG)

EXPECTED_PHP_FILE_PERMISSION = 0o444

FindingRecord = RecordDescriptor(
    "ioc/hit",
    [
        ("string", "type"),
        ("string", "alert"),
        ("string", "confidence"),
        ("string", "path"),
    ],
)


def load_config(config_path: str) -> ChecksConfig:
    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        return ChecksConfig(**data)

    except Exception as e:
        logger.exception(f"Error loading config: {e}")
        sys.exit(1)


def check_target(target: Target, checks: list[ValidCheckType], output_dir: str) -> list[FindingRecord]:
    findings = []
    for check in checks:
        if not hasattr(check_functions, check.check):
            logger.warning(f"Invalid check requested: {check.check}. Skipping.")
            continue

        fn = getattr(check_functions, check.check)

        logger.debug(f"Calling check: {check.check}, {check.args}")
        args = dict(check.args)
        if check.check == "core_dump":
            args["output_dir"] = output_dir
        try:
            for finding in fn(target, confidence=check.confidence, **args):
                logger.debug(f"Finding: {finding}")
                findings.append(finding)
        except Exception as e:
            logger.error(f"Exception {e} in {check.check}. Skipping")
    return findings


def check_targets(
    target_paths: list[str], organisation_name: str, checks_to_run: list[str], config: ChecksConfig
) -> None:
    for path in target_paths:
        logger.info(f"----------------------- Checking image {Path(path).name} -----------------------")

        target = Target.open(path)

        output_dir = os.path.join(
            "output", organisation_name, datetime.now().strftime("%Y%m%d-%H%M%S"), Path(path).name
        )

        config.checks = [check for check in config.checks if check.check in checks_to_run or "all" in checks_to_run]
        target_findings = check_target(target=target, checks=config.checks, output_dir=output_dir)
        if len(target_findings) == 0:
            logger.info("[*] No hits found for IOC checks.")
        else:
            logger.info("")
            logger.info("********************************************************************************")
            logger.info("***                                                                          ***")
            logger.info("*** There were findings for Indicators of Compromise.                        ***")
            logger.info("*** Please consider performing further forensic investigation of the system. ***")
            logger.info("***                                                                          ***")
            logger.info("********************************************************************************")
            logger.info("")
            # Display in table format
            table_entries = []
            for finding in target_findings:
                table_entries.append(
                    {
                        "confidence": finding.confidence,
                        "type": finding.type,
                        "alert": finding.alert,
                        "artefact_location": finding.path,
                    }
                )
            logger.info("\n" + tabulate(table_entries, headers="keys"))

            try:
                os.makedirs(output_dir, exist_ok=True)
                with open(os.path.join(output_dir, "findings.jsonl"), "w+") as f:
                    f.write("\n".join([json.dumps(x) for x in table_entries]))

                with open(os.path.join(output_dir, "checks.yaml"), "w+") as f:
                    f.write(yaml.dump(json.loads(config.model_dump_json())))
                logger.info(f"Wrote output to {output_dir}/[findings.jsonl|checks.yaml]")
            except Exception:
                logging.error(f"failure writing to {output_dir}")

        logger.info(f"---------------- Finished checking image {Path(path).name} ------------------")

    logger.info("All targets analyzed.")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze forensic images of Citrix Netscalers for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.",
        epilog=f"Version {SCRIPT_VERSION}; released by NCSC-NL ({HELP_URL}).",
    )
    parser.add_argument(
        "targets",
        metavar="TARGETS",
        nargs="+",
        help="Target(s) to load. https://docs.dissect.tools/en/stable/advanced/targets.html#targets",
    )

    parser.add_argument(
        "--organisation",
        metavar="ORGANISATION",
        nargs="?",
        help="Organisation name",
        default="",
        type=str,
    )

    parser.add_argument(
        "--checks",
        metavar="CHECKS",
        nargs="*",
        help="Check(s) to run. default: %(default)s, choices: %(choices)s",
        choices=ALL_CHECKS + ["all"],
        default="all",
        type=str,
    )

    parser.add_argument(
        "--config",
        "-c",
        metavar="CONFIG_FILE",
        nargs="?",
        help="Path to yaml file containing configuration with IOCs to check for. default: %(default)s",
        default="checks.yaml",
        type=str,
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )

    args = parser.parse_args()
    logger.setLevel(args.log_level)
    check_functions.set_log_level(args.log_level)

    config = load_config(args.config)
    logging.info(f"Running checks for {config.name}")

    check_targets(args.targets, organisation_name=args.organisation, checks_to_run=args.checks, config=config)


if __name__ == "__main__":
    main()
