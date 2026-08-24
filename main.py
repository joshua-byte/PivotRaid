import argparse
import time
import logging
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed

from ftp import scan_ftp
from smb import scan_smb
from ssh import scan_ssh
from vulnerabilities import query_from_fingerprint
from report import generate_html_report


# ---------------------------------------------------------------------------
# Setup Industrial Logging System
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("PivotRaid.Main")


# ---------------------------------------------------------------------------
# ASCII Art Banner
# ---------------------------------------------------------------------------

def print_banner():

    banner = r"""
 ███████████   ███                        █████    ███████████              ███      █████
░░███░░░░░███ ░░░                        ░░███    ░░███░░░░░███            ░░░      ░░███
 ░███    ░███ ████  █████ █████  ██████  ███████   ░███    ░███   ██████   ████   ███████
 ░██████████ ░░███ ░░███ ░░███  ███░░███░░░███░    ░██████████   ░░░░░███ ░░███  ███░░███
 ░███░░░░░░   ░███  ░███  ░███ ░███ ░███  ░███     ░███░░░░░███   ███████  ░███ ░███ ░███
 ░███         ░███  ░░███ ███  ░███ ░███  ░███ ███ ░███    ░███  ███░░███  ░███ ░███ ░███
 █████        █████  ░░█████   ░░██████   ░░█████  █████   █████░░████████ █████░░████████
░░░░░        ░░░░░    ░░░░░     ░░░░░  ░░░░░  ░░░░░   ░░░░░  ░░░░░  ░░░░░  ░░░░░░░░
"""

    print("\033[91m" + banner + "\033[0m")

    print(
        "\033[1mPivotRaid - Lateral Movement & Exposure Engine\033[0m"
    )

    print(
        "Developed for authorized security assessments.\n"
        + "=" * 80
        + "\n"
    )


# ---------------------------------------------------------------------------
# Risk Helpers
# ---------------------------------------------------------------------------

def calculate_vulnerability_risk(vulns):
    """
    Calculate service risk from normalized vulnerability results.

    SearchSploit findings are treated as candidates. The score reflects
    the severity of the returned candidate, not confirmed exploitability.
    """

    if not vulns:
        return 0, 0, "INFO"

    highest_score = 0

    for vuln in vulns:

        score = vuln.get(
            "score",
            0
        )

        if isinstance(score, (int, float)):
            highest_score = max(
                highest_score,
                score
            )

    if highest_score >= 90:

        verdict = "CRITICAL"

    elif highest_score >= 75:

        verdict = "HIGH"

    elif highest_score >= 50:

        verdict = "MEDIUM"

    elif highest_score > 0:

        verdict = "LOW"

    else:

        verdict = "INFO"

    # Confidence is intentionally conservative.
    #
    # SearchSploit provides candidate exploit intelligence.
    # It does not by itself prove that the target is vulnerable.

    confidence = 35

    return (
        int(highest_score),
        confidence,
        verdict
    )


# ---------------------------------------------------------------------------
# Vulnerability Enrichment
# ---------------------------------------------------------------------------

def enrich_results_with_vulnerabilities(results):
    """
    Enrich scanner results using the vulnerability correlation engine.

    Currently:
        - SSH uses its structured fingerprint.
        - SearchSploit is the sole vulnerability source.

    FTP/SMB results retain the vulnerability information already
    produced by their scanners.
    """

    for result in results:

        service_name = result.get(
            "service"
        )

        if not isinstance(
            service_name,
            str
        ):

            logger.warning(
                "Skipping result with invalid service "
                f"identifier: {service_name!r}"
            )

            continue

        service_name = service_name.upper()

        # ---------------------------------------------------------------
        # SSH
        # ---------------------------------------------------------------

        if service_name == "SSH":

            fingerprint = result.get(
                "ssh_fingerprint"
            )

            if not fingerprint:

                continue

            try:

                ssh_vulns = query_from_fingerprint(
                    fingerprint
                )

                if ssh_vulns:

                    result["vulns"] = ssh_vulns

                    score, confidence, verdict = (
                        calculate_vulnerability_risk(
                            ssh_vulns
                        )
                    )

                    result["score"] = score
                    result["confidence"] = confidence
                    result["verdict"] = verdict

                    result.setdefault(
                        "findings",
                        []
                    )

                    result["findings"].append(
                        "[INFO] SearchSploit returned "
                        f"{len(ssh_vulns)} "
                        "HIGH/CRITICAL candidate(s)."
                    )

                    logger.info(
                        "SSH vulnerability correlation "
                        f"completed: {len(ssh_vulns)} "
                        "candidate(s) identified."
                    )

                else:

                    logger.info(
                        "SearchSploit returned no "
                        "HIGH/CRITICAL SSH candidates."
                    )

            except Exception as error:

                logger.warning(
                    "SSH vulnerability correlation "
                    f"failed: {error}",
                    exc_info=True
                )

    return results


# ---------------------------------------------------------------------------
# Structured Results Printer
# ---------------------------------------------------------------------------

def print_result(result):
    """Print a standardized summary of a service scan."""

    service = result.get(
        "service",
        "UNKNOWN"
    )

    status = result.get(
        "status",
        "CLOSED"
    )

    score = result.get(
        "score",
        0
    )

    verdict = result.get(
        "verdict",
        "UNKNOWN"
    )

    print(
        f"\n[+] {service} "
        f"(Port {result.get('port')}) -> {status}"
    )

    print(
        f"    Risk Severity : "
        f"{verdict} ({score}/100)"
    )

    print(
        f"    Confidence    : "
        f"{result.get('confidence', 0)}/100"
    )

    print(
        f"    Scan Duration : "
        f"{result.get('scan_time', 0)}s"
    )

    if result.get("findings"):

        print("    Findings:")

        for finding in result["findings"]:

            print(
                f"      - {finding}"
            )

    if result.get("vulns"):

        print(
            "    Identified Vulnerabilities:"
        )

        for vulnerability in result["vulns"]:

            print(
                f"      [*] "
                f"{vulnerability.get('title', 'Unknown')} "
                f"(Severity: "
                f"{vulnerability.get('severity', 'UNKNOWN')}) "
                f"-> EDB-ID: "
                f"{vulnerability.get('id', 'N/A')}"
            )

    if result.get("attack_path"):

        print(
            "    Local Path Projection:"
        )

        for index, step in enumerate(
            result["attack_path"],
            1
        ):

            print(
                f"      {index}. {step}"
            )


# ---------------------------------------------------------------------------
# Cross-Service Threat Correlation Engine
# ---------------------------------------------------------------------------

def correlate_intelligence(results):
    """
    Acts as the brain of PivotRaid.

    At this stage vulnerability enrichment has already happened.
    This function therefore focuses on cross-service correlation
    and attack-path construction.
    """

    intel = {
        "credentials": [],
        "vulns": [],
        "services": {},
        "attack_paths": []
    }

    # -----------------------------------------------------------------------
    # Register services and vulnerabilities
    # -----------------------------------------------------------------------

    for result in results:

        service_name = result.get(
            "service"
        )

        if not isinstance(
            service_name,
            str
        ):

            logger.warning(
                "Ignoring scanner result with invalid "
                f"service identifier: {service_name!r}"
            )

            continue

        service_name = service_name.upper()

        intel["services"][
            service_name
        ] = result

        # ---------------------------------------------------------------
        # Credentials
        # ---------------------------------------------------------------

        if result.get(
            "weak_creds"
        ):

            intel["credentials"].append(
                (
                    service_name,
                    result["weak_creds"]
                )
            )

        # ---------------------------------------------------------------
        # Vulnerabilities
        # ---------------------------------------------------------------

        if result.get(
            "vulns"
        ):

            intel["vulns"].extend(
                result["vulns"]
            )

    # -----------------------------------------------------------------------
    # Service references
    # -----------------------------------------------------------------------

    ftp = intel["services"].get(
        "FTP",
        {}
    )

    smb = intel["services"].get(
        "SMB",
        {}
    )

    ssh = intel["services"].get(
        "SSH",
        {}
    )

    # -----------------------------------------------------------------------
    # Correlation Node A: Credential Harvesting & Reuse
    # -----------------------------------------------------------------------

    if intel["credentials"]:

        creds_str = ", ".join(
            [
                f"{service}({pair})"
                for service, pair
                in intel["credentials"]
            ]
        )

        intel["attack_paths"].append(
            "Credential Harvesting: "
            f"Reuse discovered credentials "
            f"[{creds_str}] across other "
            "infrastructure hosts."
        )

    # -----------------------------------------------------------------------
    # Correlation Node B: FTP Data Leaks to SMB Pivot
    # -----------------------------------------------------------------------

    ftp_has_creds = (
        ftp
        .get("classified_hits", {})
        .get("credentials")
    )

    if (
        ftp_has_creds
        and smb.get("status") == "OPEN"
    ):

        intel["attack_paths"].append(
            "FTP to SMB Lateral Pivot: "
            "Extract hardcoded configuration keys "
            "from FTP files -> Use credentials to "
            "access SMB Admin shares."
        )

    # -----------------------------------------------------------------------
    # Correlation Node C: Direct Remote Exploitation
    # -----------------------------------------------------------------------

    high_vulns = [
        vulnerability
        for vulnerability in intel["vulns"]
        if vulnerability.get("severity")
        in [
            "CRITICAL",
            "HIGH"
        ]
    ]

    if high_vulns:

        for vulnerability in high_vulns:

            intel["attack_paths"].append(
                "Direct Host Exploitation: "
                f"Leverage Exploit-DB candidate "
                f"(EDB-ID: {vulnerability.get('id')}) "
                "associated with an exposed service."
            )

    # -----------------------------------------------------------------------
    # Correlation Node D: Write Access Manipulation
    # -----------------------------------------------------------------------

    if (
        ftp.get("writable")
        and smb.get("status") == "OPEN"
    ):

        intel["attack_paths"].append(
            "Payload Drop Pivot: "
            "Upload persistent payload "
            "via FTP write permissions -> "
            "Trigger execution or capture "
            "domain credentials."
        )

    # -----------------------------------------------------------------------
    # SSH metadata
    # -----------------------------------------------------------------------

    if ssh:

        ssh_fingerprint = ssh.get(
            "ssh_fingerprint",
            {}
        )

        identification = ssh_fingerprint.get(
            "identification",
            {}
        )

        if identification.get(
            "software"
        ):

            logger.info(
                "SSH fingerprint correlated: "
                f"{identification.get('software')} "
                f"{identification.get('version', '')}"
            )

    return intel


# ---------------------------------------------------------------------------
# Assessment Summarizer
# ---------------------------------------------------------------------------

def display_summary(
    results,
    total_time
):
    """Display the executive security summary."""

    print(
        "\n" + "=" * 80
    )

    print(
        "EXECUTIVE SECURITY SUMMARY"
    )

    print(
        "=" * 80
    )

    results_sorted = sorted(
        results,
        key=lambda result: result.get(
            "score",
            0
        ),
        reverse=True
    )

    for result in results_sorted:

        print(
            f" - {result.get('service')}: "
            f"{result.get('verdict')} "
            f"(Score: {result.get('score')}/100)"
        )

    if results_sorted:

        top = results_sorted[0]

        print(
            f"\n[!] Critical Action Item: "
            f"Focus triage efforts on "
            f"{top.get('service')} "
            f"(Risk Score: "
            f"{top.get('score')}/100)"
        )

    intel = correlate_intelligence(
        results
    )

    # -----------------------------------------------------------------------
    # Vulnerability Correlation
    # -----------------------------------------------------------------------

    print(
        "\n[★] Vulnerability Correlation:"
    )

    if intel["vulns"]:

        for vulnerability in intel["vulns"]:

            print(
                f"  → [{vulnerability.get('severity')}] "
                f"{vulnerability.get('title')} "
                f"(EDB-ID: "
                f"{vulnerability.get('id')})"
            )

    else:

        print(
            "  → No HIGH/CRITICAL "
            "SearchSploit candidates correlated."
        )

    # -----------------------------------------------------------------------
    # Attack Paths
    # -----------------------------------------------------------------------

    print(
        "\n[★] Projected Attack Chains "
        "& Lateral Paths:"
    )

    if intel["attack_paths"]:

        for path in intel["attack_paths"]:

            print(
                f"  → {path}"
            )

    else:

        print(
            "  → No direct cross-service "
            "compromise chains projected."
        )

    print(
        f"\nScan Statistics: "
        f"{len(results)} services assessed "
        f"in {round(total_time, 2)} seconds.\n"
    )


# ---------------------------------------------------------------------------
# Thread-Safe Scan Coordinator
# ---------------------------------------------------------------------------

def run_scan_safe(
    scanner,
    target,
    timeout
):
    """
    Execute a scanner inside an isolated execution boundary.
    """

    service_name = (
        scanner.__name__
        .replace(
            "scan_",
            ""
        )
        .upper()
    )

    try:

        logger.debug(
            f"Launching thread for "
            f"{service_name} scanner..."
        )

        result = scanner(
            target,
            timeout=timeout
        )

        return result

    except Exception as error:

        logger.error(
            f"Thread runtime crash in "
            f"{service_name} scanner: {error}",
            exc_info=True
        )

        return {
            "service": service_name,
            "port": 0,
            "status": "CRASHED",

            "findings": [
                f"Scanner Exception: {str(error)}"
            ],

            "impact": [],

            "score": 0,

            "confidence": 0,

            "verdict": "UNKNOWN",

            "scan_time": 0,

            "vulns": []
        }


# ---------------------------------------------------------------------------
# Main Execution Entrypoint
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PivotRaid - Automated Lateral "
            "Movement & Service Exposure "
            "Core Engines."
        ),
        formatter_class=(
            argparse.ArgumentDefaultsHelpFormatter
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "IP address or hostname "
            "of target system"
        )
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help=(
            "Network connection timeout limits"
        )
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debugging log outputs"
    )

    args = parser.parse_args()

    target = args.target

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------

    if args.verbose:

        logging.getLogger(
            "PivotRaid"
        ).setLevel(
            logging.DEBUG
        )

        logger.debug(
            "Verbose debug logging enabled."
        )

    else:

        logging.getLogger(
            "PivotRaid"
        ).setLevel(
            logging.INFO
        )

    # -----------------------------------------------------------------------
    # Start Scan
    # -----------------------------------------------------------------------

    print_banner()

    logger.info(
        f"Target system locked: {target}"
    )

    start_time = time.time()

    results = []

    # -----------------------------------------------------------------------
    # Scanner Registry
    # -----------------------------------------------------------------------

    scanners = [
        scan_ftp,
        scan_smb,
        scan_ssh
    ]

    # -----------------------------------------------------------------------
    # Concurrent Scanner Execution
    # -----------------------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=len(scanners)
    ) as executor:

        futures_map = {
            executor.submit(
                run_scan_safe,
                scanner,
                target,
                args.timeout
            ): scanner

            for scanner in scanners
        }

        for future in as_completed(
            futures_map
        ):

            result = future.result()

            results.append(
                result
            )

    # -----------------------------------------------------------------------
    # Vulnerability Enrichment
    #
    # This now happens BEFORE print_result(), so SSH's SearchSploit
    # findings and calculated risk are visible in the normal service output.
    # -----------------------------------------------------------------------

    results = enrich_results_with_vulnerabilities(
        results
    )

    # -----------------------------------------------------------------------
    # Print Final Enriched Results
    # -----------------------------------------------------------------------

    for result in results:

        print_result(
            result
        )

    total_time = (
        time.time()
        - start_time
    )

    # -----------------------------------------------------------------------
    # Executive Summary
    # -----------------------------------------------------------------------

    display_summary(
        results,
        total_time
    )

    # -----------------------------------------------------------------------
    # HTML Report
    # -----------------------------------------------------------------------

    try:

        generate_html_report(
            results,
            target
        )

    except Exception as error:

        logger.error(
            "Failed to compile the final "
            f"HTML report: {error}",
            exc_info=True
        )


# ---------------------------------------------------------------------------
# Program Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n\n[!] Execution interrupted "
            "by operator. Exiting."
        )

        sys.exit(1)
