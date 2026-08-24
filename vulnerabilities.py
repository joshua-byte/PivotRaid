import subprocess
import json
import shutil
import logging


logger = logging.getLogger("PivotRaid.Vulns")


# ============================================================================
# Normalize SearchSploit Results
# ============================================================================

def normalize_exploit_result(
    exploit,
    product,
    version,
    platform
):
    """
    Convert a raw SearchSploit JSON result into the
    normalized PivotRaid vulnerability structure.

    This function does not determine exploitability.
    It only normalizes SearchSploit output.
    """

    title = exploit.get(
        "Title",
        ""
    )

    path = exploit.get(
        "Path",
        ""
    )

    edb_id = str(
        exploit.get(
            "EDB-ID",
            ""
        )
    )

    severity, score = analyze_exploit_severity(
        title
    )

    return {
        "id": edb_id,

        "title": title,

        "path": path,

        "severity": severity,

        "score": score,

        "url": (
            "https://www.exploit-db.com/"
            f"exploits/{edb_id}"
        ),

        "lookup": {
            "product": product,
            "version": version,
            "platform": platform
        }
    }


# ============================================================================
# SearchSploit Query Engine
# ============================================================================

def query_searchsploit(
    product,
    version="",
    platform="",
    service=""
):
    """
    Query the local SearchSploit database using structured
    service evidence.

    SearchSploit is the sole vulnerability intelligence
    source used by PivotRaid.

    This function performs lookup only. It does not
    establish exploitability.
    """

    product_clean = (
        product or ""
    ).lower().strip()

    version_clean = (
        version or ""
    ).lower().strip()

    platform_clean = (
        platform or ""
    ).lower().strip()

    service_clean = (
        service or ""
    ).lower().strip()

    if not product_clean:

        logger.debug(
            "SearchSploit lookup skipped: "
            "product was not identified."
        )

        return []

    if not shutil.which("searchsploit"):

        logger.warning(
            "SearchSploit binary not found "
            "in system PATH."
        )

        return []

    # ------------------------------------------------------------------------
    # Product + version
    #
    # Platform and service are retained as contextual
    # metadata rather than automatically added to the
    # SearchSploit query.
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
        "SearchSploit lookup: "
        f"{search_term}"
    )

    try:

        process = subprocess.run(
            [
                "searchsploit",
                "--json",
                search_term
            ],

            stdout=subprocess.PIPE,

            stderr=subprocess.PIPE,

            text=True,

            timeout=5
        )

        if not process.stdout.strip():

            logger.debug(
                "SearchSploit returned no output "
                f"for: {search_term}"
            )

            return []

        data = json.loads(
            process.stdout
        )

        results = data.get(
            "RESULTS_EXPLOIT",
            []
        )

        logger.debug(
            "SearchSploit returned "
            f"{len(results)} raw result(s) "
            f"for: {search_term}"
        )

        filtered_vulns = []

        for exploit in results:

            normalized = normalize_exploit_result(
                exploit=exploit,
                product=product,
                version=version,
                platform=platform
            )

            if normalized["severity"] in [
                "HIGH",
                "CRITICAL"
            ]:

                filtered_vulns.append(
                    normalized
                )

        logger.info(
            "SearchSploit produced "
            f"{len(filtered_vulns)} HIGH/CRITICAL "
            f"candidate(s) for {search_term}"
        )

        return filtered_vulns

    except subprocess.TimeoutExpired:

        logger.warning(
            "SearchSploit query timed out "
            f"for term: {search_term}"
        )

        return []

    except json.JSONDecodeError as error:

        logger.warning(
            "SearchSploit returned invalid JSON "
            f"for {search_term}: {error}"
        )

        return []

    except OSError as error:

        logger.warning(
            "SearchSploit execution failed: "
            f"{error}"
        )

        return []

    except Exception as error:

        logger.debug(
            "Unexpected SearchSploit error: "
            f"{error}"
        )

        return []


# ============================================================================
# Structured Fingerprint → SearchSploit
# ============================================================================

def query_from_fingerprint(
    fingerprint
):
    """
    Query SearchSploit directly from a structured
    service fingerprint.

    Expected structure:

        {
            "service": {
                "name": "ssh"
            },

            "identification": {
                "software": "OpenSSH",
                "version": "4.7p1",
                "platform": "Ubuntu"
            }
        }
    """

    if not fingerprint:
        return []

    service_info = fingerprint.get(
        "service",
        {}
    )

    service = service_info.get(
        "name",
        ""
    )

    identification = fingerprint.get(
        "identification",
        {}
    )

    product = identification.get(
        "software"
    )

    version = identification.get(
        "version"
    )

    platform = identification.get(
        "platform"
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
        service=service
    )


# ============================================================================
# Exploit Severity Heuristic
# ============================================================================

def analyze_exploit_severity(
    title
):
    """
    Categorize SearchSploit exploit titles into
    PivotRaid threat classes.

    This is a reporting heuristic.

    It is NOT a determination that the target is
    actually vulnerable or exploitable.
    """

    title_lower = (
        title or ""
    ).lower()

    # ------------------------------------------------------------------------
    # Critical
    # ------------------------------------------------------------------------

    if any(
        keyword in title_lower
        for keyword in [
            "rce",
            "remote code execution",
            "auth bypass",
            "authentication bypass",
            "backdoor"
        ]
    ):

        return "CRITICAL", 95

    # ------------------------------------------------------------------------
    # High
    # ------------------------------------------------------------------------

    elif any(
        keyword in title_lower
        for keyword in [
            "buffer overflow",
            "privilege escalation",
            "arbitrary file",
            "upload"
        ]
    ):

        return "HIGH", 80

    # ------------------------------------------------------------------------
    # Medium
    # ------------------------------------------------------------------------

    elif any(
        keyword in title_lower
        for keyword in [
            "disclosure",
            "traversal",
            "dos",
            "denial of service"
        ]
    ):

        return "MEDIUM", 50

    # ------------------------------------------------------------------------
    # Low
    # ------------------------------------------------------------------------

    return "LOW", 25
