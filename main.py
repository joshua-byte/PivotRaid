import argparse
import logging
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed

from ftp import scan_ftp
from smb import scan_smb
from ssh import scan_ssh

from vulnerabilities import query_from_fingerprint

from risk_engine import assess_risk
from correlation_engine import correlate_results

from report import generate_html_report


logger = logging.getLogger("PivotRaid.Main")


# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)


# ============================================================================
# Banner
# ============================================================================

def print_banner():

    banner = r"""
 ███████████   ███                        █████    ███████████              ███      █████
░░███░░░░░███ ░░░                        ░░███    ░░███░░░░░███            ░░░      ░░███
 ░███    ░███ ████  █████ █████  ██████  ███████   ░███    ░███   ██████   ████   ███████
 ░██████████ ░░███ ░░███ ░░███  ███░░███░░░███░    ░██████████   ░░░░░███ ░░███  ███░░███
 ░███░░░░░░   ░███  ░███  ░███ ░███ ░███  ░███     ░███░░░░░███   ███████  ░███ ░███ ░███
 ░███         ░███  ░░███ ███  ░███ ░███  ░███ ███ ░███    ░███  ███░░███  ░███ ░███ ░███
 █████        █████  ░░█████   ░░██████   ░░█████  █████   █████░░████████ █████░░████████
░░░░░        ░░░░░    ░░░░░     ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░░░░
"""

    print(
        "\033[91m"
        + banner
        + "\033[0m"
    )

    print(
        "\033[1m"
        "PivotRaid - Lateral Movement & Exposure Engine"
        "\033[0m"
    )

    print(
        "Developed for authorized security assessments.\n"
        + "=" * 80
        + "\n"
    )


# ============================================================================
# Vulnerability Enrichment
# ============================================================================

def _has_vulnerability_discovery_finding(
    result,
):
    """
    Determine whether the service already contains the standardized
    vulnerability-discovery finding.

    This makes enrichment idempotent.
    """

    findings = result.get(
        "findings",
        [],
    )

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        if (
            finding.get("category")
            == "vulnerability_discovery"
        ):

            return True

    return False


def _add_vulnerability_discovery_finding(
    result,
    candidate_count,
    source="Exploit-DB/SearchSploit",
):
    """
    Add one informational vulnerability-discovery observation.

    This does NOT represent a vulnerability.

    It only records that vulnerability intelligence returned
    candidate records.
    """

    if _has_vulnerability_discovery_finding(
        result
    ):
        return

    result.setdefault(
        "findings",
        [],
    )

    result[
        "findings"
    ].append({

        "title": (
            "SearchSploit identified "
            f"{candidate_count} vulnerability "
            "candidate(s)"
        ),

        "severity": "INFO",

        "confidence": "HIGH",

        "category": (
            "vulnerability_discovery"
        ),

        "evidence": {

            "candidate_count": (
                candidate_count
            ),

            "source": source,
        },

        "impact": (
            "SearchSploit candidates indicate "
            "potentially relevant exploit records. "
            "They do not establish target "
            "vulnerability or exploitability."
        ),
    })


def enrich_results_with_vulnerabilities(
    results,
):
    """
    Enrich structured scanner results with vulnerability candidates.

    Vulnerability discovery is delegated to vulnerabilities.py.

    IMPORTANT DATA-MODEL RULE
    -------------------------

    Observed security conditions belong in:

        result["findings"]

    Vulnerability intelligence candidates belong in:

        result["vulns"]

    A SearchSploit candidate must NOT automatically become a
    HIGH or CRITICAL finding.

    This function does NOT:

        - calculate risk
        - determine exploitability
        - confirm vulnerabilities
        - generate attack paths
    """

    for result in results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        service_name = result.get(
            "service",
            "UNKNOWN",
        )

        if not isinstance(
            service_name,
            str,
        ):

            logger.warning(
                "Skipping result with invalid "
                "service identifier: %r",
                service_name,
            )

            continue

        service_name = (
            service_name
            .upper()
            .strip()
        )

        # ====================================================================
        # SSH
        # ====================================================================

        if service_name != "SSH":
            continue

        fingerprint = result.get(
            "ssh_fingerprint"
        )

        if not fingerprint:

            logger.debug(
                "SSH result does not contain "
                "a fingerprint; vulnerability "
                "enrichment skipped."
            )

            continue

        try:

            ssh_vulns = (
                query_from_fingerprint(
                    fingerprint
                )
            )

            if not isinstance(
                ssh_vulns,
                list,
            ):

                logger.warning(
                    "SSH vulnerability lookup "
                    "returned invalid type: %s",
                    type(
                        ssh_vulns
                    ).__name__,
                )

                ssh_vulns = []

            # ---------------------------------------------------------------
            # Replace candidates rather than blindly extending them.
            #
            # This prevents duplicate vulnerability records if enrichment
            # is accidentally invoked more than once.
            # ---------------------------------------------------------------

            result[
                "vulns"
            ] = ssh_vulns

            if ssh_vulns:

                _add_vulnerability_discovery_finding(
                    result=result,
                    candidate_count=len(
                        ssh_vulns
                    ),
                )

                logger.info(
                    "SSH vulnerability enrichment "
                    "completed: %d candidate(s)",
                    len(
                        ssh_vulns
                    ),
                )

            else:

                logger.info(
                    "No SearchSploit candidates "
                    "identified for SSH."
                )

        except Exception as error:

            logger.warning(
                "SSH vulnerability enrichment failed: %s",
                error,
                exc_info=True,
            )

    return results


# ============================================================================
# Structured Result Printer
# ============================================================================

def print_result(
    result,
):
    """
    Print one normalized service result.
    """

    service = result.get(
        "service",
        "UNKNOWN",
    )

    status = result.get(
        "status",
        "UNKNOWN",
    )

    print(
        f"\n[+] {service} "
        f"(Port {result.get('port')}) -> {status}"
    )

    # ========================================================================
    # Findings
    # ========================================================================

    findings = result.get(
        "findings",
        [],
    )

    if findings:

        print(
            "    Findings:"
        )

        for finding in findings:

            if isinstance(
                finding,
                dict,
            ):

                severity = finding.get(
                    "severity",
                    "INFO",
                )

                confidence = finding.get(
                    "confidence",
                    "LOW",
                )

                title = finding.get(
                    "title",
                    "Unnamed finding",
                )

                print(
                    f"      - [{severity}] "
                    f"{title} "
                    f"(Confidence: {confidence})"
                )

            else:

                print(
                    f"      - {finding}"
                )

    # ========================================================================
    # Vulnerability candidates
    # ========================================================================

    vulnerabilities = result.get(
        "vulns",
        [],
    )

    if vulnerabilities:

        print(
            "    Vulnerability Candidates:"
        )

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict,
            ):
                continue

            print(
                "      [*] "
                f"{vulnerability.get('title', 'Unknown')} "
                f"(Severity: "
                f"{vulnerability.get('severity', 'UNKNOWN')}) "
                f"-> EDB-ID: "
                f"{vulnerability.get('id', 'N/A')}"
            )


# ============================================================================
# Risk Summary Printer
# ============================================================================

def print_risk_summary(
    risk,
):
    """
    Print the target-level risk assessment.
    """

    if not risk:
        return

    print(
        "\n"
        + "=" * 80
    )

    print(
        "TARGET RISK ASSESSMENT"
    )

    print(
        "=" * 80
    )

    print(
        f"Risk Score    : "
        f"{risk.get('score', 0)}/100"
    )

    print(
        f"Severity      : "
        f"{risk.get('severity', 'INFO')}"
    )

    print(
        f"Confidence    : "
        f"{risk.get('confidence', 'LOW')}"
    )

    print(
        f"Findings      : "
        f"{risk.get('finding_count', 0)}"
    )

    print(
        f"Services      : "
        f"{risk.get('service_count', 0)}"
    )

    print(
        f"Confirmed Vulns: "
        f"{risk.get('confirmed_vulnerabilities', 0)}"
    )

    print(
        f"Vuln Candidates: "
        f"{risk.get('vulnerability_candidates', 0)}"
    )

    verdict = risk.get(
        "verdict"
    )

    if verdict:

        print(
            "\nVerdict:\n"
            f"  {verdict}"
        )

    # ========================================================================
    # Risk factors
    # ========================================================================

    factors = risk.get(
        "risk_factors",
        [],
    )

    if factors:

        print(
            "\nRisk Factors:"
        )

        for factor in factors:

            if not isinstance(
                factor,
                dict,
            ):
                continue

            print(
                "  → "
                f"[{factor.get('severity', 'INFO')}] "
                f"{factor.get('title', 'Unknown')} "
                f"({factor.get('contribution', 0)} points)"
            )


# ============================================================================
# Correlation Summary Printer
# ============================================================================

def print_correlation_summary(
    correlation,
):
    """
    Print cross-service relationships and potential exposure paths.
    """

    if not correlation:
        return

    print(
        "\n"
        + "=" * 80
    )

    print(
        "CROSS-SERVICE CORRELATION"
    )

    print(
        "=" * 80
    )

    # ========================================================================
    # Relationships
    # ========================================================================

    relationships = correlation.get(
        "relationships",
        [],
    )

    if relationships:

        print(
            "\nRelationships:"
        )

        for relationship in relationships:

            if not isinstance(
                relationship,
                dict,
            ):
                continue

            print(
                "  → "
                f"{relationship.get('source')} "
                "-> "
                f"{relationship.get('destination')} "
                f"[{relationship.get('severity')}] "
                f"{relationship.get('relationship')}"
            )

    else:

        print(
            "\nRelationships:\n"
            "  → None identified."
        )

    # ========================================================================
    # Potential exposure paths
    # ========================================================================

    paths = correlation.get(
        "attack_paths",
        [],
    )

    if paths:

        print(
            "\nPotential Exposure Paths:"
        )

        for index, path in enumerate(
            paths,
            1,
        ):

            if not isinstance(
                path,
                dict,
            ):
                continue

            print(
                f"\n  {index}. "
                f"{path.get('name', 'Unnamed path')}"
            )

            print(
                f"     Severity   : "
                f"{path.get('severity', 'INFO')}"
            )

            print(
                f"     Confidence : "
                f"{path.get('confidence', 'LOW')}"
            )

            rationale = path.get(
                "rationale"
            )

            if rationale:

                print(
                    f"     Rationale  : "
                    f"{rationale}"
                )

            steps = path.get(
                "steps",
                [],
            )

            for step_index, step in enumerate(
                steps,
                1,
            ):

                if not isinstance(
                    step,
                    dict,
                ):
                    continue

                service = step.get(
                    "service",
                    "UNKNOWN",
                )

                observation = step.get(
                    "observation",
                    "",
                )

                print(
                    f"       {step_index}. "
                    f"[{service}] "
                    f"{observation}"
                )

    else:

        print(
            "\nPotential Exposure Paths:\n"
            "  → None identified."
        )


# ============================================================================
# Thread-Safe Scanner Wrapper
# ============================================================================

def run_scan_safe(
    scanner,
    target,
    timeout,
):
    """
    Execute a scanner inside an isolated execution boundary.

    A scanner failure does not terminate the entire assessment.
    """

    service_name = (
        scanner.__name__
        .replace(
            "scan_",
            "",
        )
        .upper()
    )

    try:

        logger.debug(
            "Launching %s scanner",
            service_name,
        )

        result = scanner(
            target,
            timeout=timeout,
        )

        if not isinstance(
            result,
            dict,
        ):

            raise TypeError(
                f"{service_name} scanner returned "
                f"{type(result).__name__}, expected dict"
            )

        return result

    except Exception as error:

        logger.error(
            "Scanner failure in %s: %s",
            service_name,
            error,
            exc_info=True,
        )

        return {

            "service": service_name,

            "port": 0,

            "status": "CRASHED",

            "findings": [

                {
                    "title": (
                        f"{service_name} scanner "
                        "terminated unexpectedly"
                    ),

                    "severity": "MEDIUM",

                    "confidence": "HIGH",

                    "category": "scanner_error",

                    "evidence": {
                        "error": str(error),
                    },

                    "impact": (
                        "The service could not be assessed "
                        "normally."
                    ),
                }
            ],

            "impact": [],

            "vulns": [],

            "score": 0,

            "confidence": 0,

            "verdict": "UNKNOWN",

            "scan_time": 0,
        }


# ============================================================================
# Executive Summary
# ============================================================================

def display_summary(
    results,
    risk,
    correlation,
    total_time,
):
    """
    Display the final executive security summary.
    """

    print(
        "\n"
        + "=" * 80
    )

    print(
        "EXECUTIVE SECURITY SUMMARY"
    )

    print(
        "=" * 80
    )

    # ========================================================================
    # Target risk
    # ========================================================================

    if risk:

        print(
            f"\nTarget Risk: "
            f"{risk.get('severity', 'INFO')} "
            f"({risk.get('score', 0)}/100)"
        )

        print(
            f"Assessment Confidence: "
            f"{risk.get('confidence', 'LOW')}"
        )

    # ========================================================================
    # Services
    # ========================================================================

    print(
        "\nServices Assessed:"
    )

    for result in results:

        print(
            f"  - "
            f"{result.get('service', 'UNKNOWN')}: "
            f"{result.get('status', 'UNKNOWN')}"
        )

    # ========================================================================
    # Correlation
    # ========================================================================

    if correlation:

        relationship_count = len(
            correlation.get(
                "relationships",
                [],
            )
        )

        path_count = len(
            correlation.get(
                "attack_paths",
                [],
            )
        )

        print(
            f"\nCross-Service Relationships: "
            f"{relationship_count}"
        )

        print(
            f"Potential Exposure Paths: "
            f"{path_count}"
        )

    print(
        f"\nScan Statistics: "
        f"{len(results)} services assessed "
        f"in {round(total_time, 2)} seconds."
    )

    print(
        "=" * 80
    )


# ============================================================================
# Main
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PivotRaid - Automated Lateral "
            "Movement & Service Exposure "
            "Assessment Engine."
        ),
        formatter_class=(
            argparse.ArgumentDefaultsHelpFormatter
        ),
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "IP address or hostname "
            "of target system"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help=(
            "Network connection timeout"
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=(
            "Enable debugging log output"
        ),
    )

    args = parser.parse_args()

    target = args.target

    # ========================================================================
    # Logging
    # ========================================================================

    pivotraid_logger = logging.getLogger(
        "PivotRaid"
    )

    if args.verbose:

        pivotraid_logger.setLevel(
            logging.DEBUG
        )

        logger.debug(
            "Verbose debug logging enabled."
        )

    else:

        pivotraid_logger.setLevel(
            logging.INFO
        )

    # ========================================================================
    # Start
    # ========================================================================

    print_banner()

    logger.info(
        "Target system locked: %s",
        target,
    )

    start_time = time.time()

    results = []

    # ========================================================================
    # Scanner Registry
    # ========================================================================

    scanners = [
        scan_ftp,
        scan_smb,
        scan_ssh,
    ]

    # ========================================================================
    # Concurrent Scanning
    # ========================================================================

    with ThreadPoolExecutor(
        max_workers=len(scanners)
    ) as executor:

        futures_map = {

            executor.submit(
                run_scan_safe,
                scanner,
                target,
                args.timeout,
            ): scanner

            for scanner in scanners
        }

        for future in as_completed(
            futures_map
        ):

            result = future.result()

            if result:

                results.append(
                    result
                )

    # ========================================================================
    # Stable output ordering
    # ========================================================================

    service_order = {
        "FTP": 1,
        "SMB": 2,
        "SSH": 3,
    }

    results.sort(
        key=lambda result: service_order.get(
            str(
                result.get(
                    "service",
                    "",
                )
            ).upper(),
            99,
        )
    )

    # ========================================================================
    # Vulnerability Enrichment
    # ========================================================================

    results = (
        enrich_results_with_vulnerabilities(
            results
        )
    )

    # ========================================================================
    # Print individual service results
    # ========================================================================

    for result in results:

        print_result(
            result
        )

    # ========================================================================
    # Central Risk Engine
    # ========================================================================

    try:

        risk = assess_risk(
            results
        )

    except Exception as error:

        logger.error(
            "Risk engine failure: %s",
            error,
            exc_info=True,
        )

        risk = {

            "score": 0,

            "severity": "UNKNOWN",

            "confidence": "LOW",

            "verdict": (
                "Risk assessment failed."
            ),

            "finding_count": 0,

            "service_count": len(
                results
            ),

            "confirmed_vulnerabilities": 0,

            "vulnerability_candidates": 0,

            "risk_factors": [],

            "services": {},
        }

    # ========================================================================
    # Correlation Engine
    # ========================================================================

    try:

        correlation = correlate_results(
            results
        )

    except Exception as error:

        logger.error(
            "Correlation engine failure: %s",
            error,
            exc_info=True,
        )

        correlation = {

            "relationships": [],

            "attack_paths": [],
        }

    # ========================================================================
    # Central intelligence output
    # ========================================================================

    print_risk_summary(
        risk
    )

    print_correlation_summary(
        correlation
    )

    # ========================================================================
    # Timing
    # ========================================================================

    total_time = (
        time.time()
        - start_time
    )

    # ========================================================================
    # Executive Summary
    # ========================================================================

    display_summary(
        results=results,
        risk=risk,
        correlation=correlation,
        total_time=total_time,
    )

    # ========================================================================
    # HTML Report
    # ========================================================================

    try:

        generate_html_report(
            results,
            target,
        )

        logger.info(
            "HTML report generated successfully."
        )

    except Exception as error:

        logger.error(
            "Failed to compile final HTML report: %s",
            error,
            exc_info=True,
        )


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n\n"
            "[!] Execution interrupted by operator. "
            "Exiting."
        )

        sys.exit(1)
