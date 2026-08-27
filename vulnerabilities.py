import json
import logging
import shutil
import subprocess


logger = logging.getLogger("PivotRaid.Vulns")


# ============================================================================
# Constants
# ============================================================================

VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


# ============================================================================
# Exploit Severity Heuristic
# ============================================================================

def analyze_exploit_severity(title):
    """
    Categorize a SearchSploit exploit title into a PivotRaid
    reporting severity.

    IMPORTANT:
        This is a title-based heuristic.

        It does NOT establish:
            - target vulnerability
            - exploitability
            - successful exploitation
            - applicability to the target configuration

    Returns:
        (severity, heuristic_score)
    """

    title_lower = (title or "").lower()

    # ------------------------------------------------------------------------
    # Critical
    # ------------------------------------------------------------------------

    if any(
        keyword in title_lower
        for keyword in [
            "remote code execution",
            "remote code exec",
            "rce",
            "authentication bypass",
            "auth bypass",
            "command execution",
            "backdoor",
        ]
    ):
        return "CRITICAL", 95

    # ------------------------------------------------------------------------
    # High
    # ------------------------------------------------------------------------

    if any(
        keyword in title_lower
        for keyword in [
            "buffer overflow",
            "privilege escalation",
            "arbitrary file",
            "arbitrary command",
            "arbitrary code",
            "file upload",
            "remote exploit",
        ]
    ):
        return "HIGH", 80

    # ------------------------------------------------------------------------
    # Medium
    # ------------------------------------------------------------------------

    if any(
        keyword in title_lower
        for keyword in [
            "information disclosure",
            "information leak",
            "directory traversal",
            "path traversal",
            "traversal",
            "denial of service",
            "denial-of-service",
            "dos",
        ]
    ):
        return "MEDIUM", 50

    # ------------------------------------------------------------------------
    # Low
    # ------------------------------------------------------------------------

    return "LOW", 25


# ============================================================================
# Normalize SearchSploit Result
# ============================================================================

def normalize_exploit_result(
    exploit,
    product,
    version="",
    platform="",
    service="",
    query="",
    query_confidence="medium",
):
    """
    Convert a raw SearchSploit result into the canonical
    PivotRaid vulnerability-candidate structure.

    This function performs normalization only.

    It does NOT determine whether the target is vulnerable.
    """

    if not isinstance(exploit, dict):
        return None

    title = str(
        exploit.get("Title", "")
    ).strip()

    path = str(
        exploit.get("Path", "")
    ).strip()

    edb_id = str(
        exploit.get("EDB-ID", "")
    ).strip()

    if not title:
        title = "Unnamed SearchSploit result"

    severity, heuristic_score = (
        analyze_exploit_severity(title)
    )

    url = None

    if edb_id:
        url = (
            "https://www.exploit-db.com/"
            f"exploits/{edb_id}"
        )

    return {
        "id": edb_id,

        "title": title,

        "path": path,

        "severity": severity,

        # This is a heuristic reporting value.
        # It is NOT a CVSS score and NOT exploitability.
        "heuristic_score": heuristic_score,

        "url": url,

        # Explicitly identify this as a candidate.
        "status": "CANDIDATE",

        "confirmed": False,

        "exploitability": "UNKNOWN",

        "confidence": (
            str(query_confidence or "medium").upper()
        ),

        "source": "Exploit-DB/SearchSploit",

        "lookup": {
            "product": product or "",
            "version": version or "",
            "platform": platform or "",
            "service": service or "",
            "query": query or "",
        },

        # Preserve the original result for reporting/debugging.
        "raw": exploit,
    }


# ============================================================================
# SearchSploit Binary
# ============================================================================

def searchsploit_available():
    """
    Return True when SearchSploit is available in PATH.
    """

    return shutil.which("searchsploit") is not None


# ============================================================================
# Execute SearchSploit
# ============================================================================

def _run_searchsploit(search_term, timeout=5):
    """
    Execute SearchSploit and return its decoded JSON object.

    This function performs no interpretation of vulnerabilities.
    """

    if not search_term:
        return None

    try:
        process = subprocess.run(
            [
                "searchsploit",
                "--json",
                search_term,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired:
        logger.warning(
            "SearchSploit query timed out: %s",
            search_term,
        )
        return None

    except OSError as exc:
        logger.warning(
            "SearchSploit execution failed: %s",
            exc,
        )
        return None

    if process.returncode != 0:
        logger.debug(
            "SearchSploit returned exit code %s for '%s': %s",
            process.returncode,
            search_term,
            process.stderr.strip(),
        )

    if not process.stdout.strip():
        logger.debug(
            "SearchSploit returned no output for: %s",
            search_term,
        )
        return None

    try:
        return json.loads(
            process.stdout
        )

    except json.JSONDecodeError as exc:
        logger.warning(
            "Invalid SearchSploit JSON for '%s': %s",
            search_term,
            exc,
        )
        return None


# ============================================================================
# Deduplicate Results
# ============================================================================

def _deduplicate_vulnerabilities(vulnerabilities):
    """
    Remove duplicate vulnerability candidates.

    EDB-ID is preferred as the stable identifier.
    If unavailable, title/path are used.
    """

    unique = []
    seen = set()

    for vulnerability in vulnerabilities:
        edb_id = vulnerability.get("id")

        if edb_id:
            key = (
                "edb",
                edb_id,
            )
        else:
            key = (
                "fallback",
                vulnerability.get("title", "").lower(),
                vulnerability.get("path", "").lower(),
            )

        if key in seen:
            continue

        seen.add(key)
        unique.append(vulnerability)

    return unique


# ============================================================================
# SearchSploit Query Engine
# ============================================================================

def query_searchsploit(
    product,
    version="",
    platform="",
    service="",
    query_confidence="high",
    timeout=5,
):
    """
    Query the local SearchSploit database.

    SearchSploit results are returned as vulnerability CANDIDATES.

    The function does NOT establish:
        - that the target is vulnerable
        - that the exploit applies
        - that exploitation is possible
        - that exploitation succeeded
    """

    product_clean = (
        product or ""
    ).strip()

    version_clean = (
        version or ""
    ).strip()

    platform_clean = (
        platform or ""
    ).strip()

    service_clean = (
        service or ""
    ).strip()

    if not product_clean:
        logger.debug(
            "SearchSploit lookup skipped: "
            "product not identified."
        )
        return []

    if not searchsploit_available():
        logger.warning(
            "SearchSploit binary not found in PATH."
        )
        return []

    # ------------------------------------------------------------------------
    # Construct lookup term.
    #
    # Platform and service remain contextual metadata.
    # ------------------------------------------------------------------------

    search_terms = [
        product_clean
    ]

    if version_clean:
        search_terms.append(
            version_clean
        )

    search_term = " ".join(
        search_terms
    )

    logger.info(
        "SearchSploit lookup: %s",
        search_term,
    )

    data = _run_searchsploit(
        search_term,
        timeout=timeout,
    )

    if not data:
        return []

    results = data.get(
        "RESULTS_EXPLOIT",
        [],
    )

    if not isinstance(results, list):
        logger.debug(
            "Unexpected SearchSploit result structure "
            "for: %s",
            search_term,
        )
        return []

    logger.debug(
        "SearchSploit returned %d raw result(s) for %s",
        len(results),
        search_term,
    )

    vulnerabilities = []

    for exploit in results:
        normalized = normalize_exploit_result(
            exploit=exploit,
            product=product_clean,
            version=version_clean,
            platform=platform_clean,
            service=service_clean,
            query=search_term,
            query_confidence=query_confidence,
        )

        if normalized:
            vulnerabilities.append(
                normalized
            )

    vulnerabilities = _deduplicate_vulnerabilities(
        vulnerabilities
    )

    logger.info(
        "SearchSploit produced %d vulnerability "
        "candidate(s) for %s",
        len(vulnerabilities),
        search_term,
    )

    return vulnerabilities


# ============================================================================
# Structured Fingerprint → SearchSploit
# ============================================================================

def query_from_fingerprint(
    fingerprint,
    timeout=5,
):
    """
    Query SearchSploit from a canonical PivotRaid
    service fingerprint.

    Expected structure:

        {
            "service": {
                "name": "ssh"
            },

            "identification": {
                "software": "OpenSSH",
                "version": "8.9p1",
                "platform": "Ubuntu"
            }
        }
    """

    if not fingerprint:
        return []

    service_info = fingerprint.get(
        "service",
        {},
    )

    identification = fingerprint.get(
        "identification",
        {},
    )

    service = service_info.get(
        "name",
        "",
    )

    product = identification.get(
        "software",
    )

    version = identification.get(
        "version",
    )

    platform = identification.get(
        "platform",
    )

    if not product:
        logger.debug(
            "Fingerprint does not contain "
            "an identifiable product."
        )
        return []

    return query_searchsploit(
        product=product,
        version=version or "",
        platform=platform or "",
        service=service,
        query_confidence="high" if version else "low",
        timeout=timeout,
    )


# ============================================================================
# Batch Fingerprint Lookup
# ============================================================================

def query_multiple_fingerprints(
    fingerprints,
    timeout=5,
):
    """
    Run SearchSploit against multiple structured fingerprints.

    Duplicate vulnerability candidates are removed.
    """

    if not fingerprints:
        return []

    all_vulnerabilities = []

    for fingerprint in fingerprints:
        results = query_from_fingerprint(
            fingerprint,
            timeout=timeout,
        )

        all_vulnerabilities.extend(
            results
        )

    return _deduplicate_vulnerabilities(
        all_vulnerabilities
    )


# ============================================================================
# Vulnerability Summary
# ============================================================================

def summarize_vulnerabilities(
    vulnerabilities
):
    """
    Produce a compact summary of vulnerability candidates.

    This summary is intended for reporting and risk-engine input.
    """

    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "confirmed": 0,
        "candidates": 0,
    }

    for vulnerability in vulnerabilities or []:
        summary["total"] += 1

        severity = str(
            vulnerability.get(
                "severity",
                "LOW",
            )
        ).upper()

        if severity == "CRITICAL":
            summary["critical"] += 1

        elif severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        else:
            summary["low"] += 1

        if vulnerability.get("confirmed"):
            summary["confirmed"] += 1

        else:
            summary["candidates"] += 1

    return summary
