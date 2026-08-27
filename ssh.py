import json
import re
import socket
import time
import logging


logger = logging.getLogger("PivotRaid.SSH")


# ============================================================================
# 1. RAW SSH BANNER
# ============================================================================

def get_ssh_banner(
    host,
    port=22,
    timeout=5,
):
    """
    Collect the SSH identification banner directly from TCP.

    No authentication is performed.
    No username is required.
    No cryptographic negotiation is performed.
    """

    sock = None
    start_time = time.time()

    try:

        sock = socket.create_connection(
            (host, port),
            timeout=timeout,
        )

        sock.settimeout(
            timeout
        )

        data = b""

        while len(data) < 4096:

            chunk = sock.recv(
                1024
            )

            if not chunk:
                break

            data += chunk

            if b"\n" in data:
                break

        # SSH servers may send pre-banner lines.
        # Find the actual SSH identification line.

        for line in data.splitlines():

            line = line.strip()

            if line.startswith(b"SSH-"):

                banner = line.decode(
                    "utf-8",
                    errors="replace",
                )

                logger.debug(
                    "SSH banner collected from %s:%s in %.2fs",
                    host,
                    port,
                    time.time() - start_time,
                )

                return banner

        return None

    except (
        socket.timeout,
        OSError,
    ) as exc:

        logger.debug(
            "SSH banner collection failed for %s:%s - %s",
            host,
            port,
            exc,
        )

        return None

    finally:

        if sock is not None:

            try:
                sock.close()

            except OSError:
                pass


# ============================================================================
# 2. SSH SERVER INFORMATION
# ============================================================================

def get_ssh_server_info(
    banner,
):
    """
    Parse an SSH identification banner.

    Example:

        SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0

    becomes approximately:

        protocol = 2.0
        software = OpenSSH
        version = 8.9p1
        platform = Ubuntu
    """

    server_info = {

        "raw_banner": banner,

        "protocol": None,

        "software": None,

        "version": None,

        "platform": None,

        "platform_version": None,
    }

    if not banner:
        return server_info

    # ========================================================================
    # Protocol
    # ========================================================================

    protocol_match = re.search(
        r"^SSH-([0-9.]+)-",
        banner,
    )

    if protocol_match:

        server_info[
            "protocol"
        ] = protocol_match.group(
            1
        )

    # ========================================================================
    # Software / Implementation
    # ========================================================================

    software_match = re.search(
        r"^SSH-[0-9.]+-([^ ]+)",
        banner,
    )

    if software_match:

        software_string = (
            software_match.group(
                1
            )
        )

        # --------------------------------------------------------------------
        # OpenSSH
        # --------------------------------------------------------------------

        openssh_match = re.match(
            r"(OpenSSH)[_-]([0-9][A-Za-z0-9._-]*)",
            software_string,
        )

        if openssh_match:

            server_info[
                "software"
            ] = openssh_match.group(
                1
            )

            server_info[
                "version"
            ] = openssh_match.group(
                2
            )

        else:

            # Generic SSH implementation

            server_info[
                "software"
            ] = software_string

    # ========================================================================
    # Platform / Distribution
    # ========================================================================

    banner_lower = banner.lower()

    platform_patterns = {

        "Ubuntu": r"ubuntu",

        "Debian": r"debian",

        "CentOS": r"centos",

        "RHEL": r"rhel",

        "Fedora": r"fedora",

        "FreeBSD": r"freebsd",

        "OpenBSD": r"openbsd",

        "NetBSD": r"netbsd",
    }

    for (
        platform,
        pattern,
    ) in platform_patterns.items():

        if re.search(
            pattern,
            banner_lower,
        ):

            server_info[
                "platform"
            ] = platform

            break

    # ========================================================================
    # Platform Version
    # ========================================================================

    if server_info[
        "platform"
    ]:

        platform = server_info[
            "platform"
        ]

        platform_version_match = re.search(
            rf"{re.escape(platform)}[-_/]([A-Za-z0-9._-]+)",
            banner,
            re.IGNORECASE,
        )

        if platform_version_match:

            server_info[
                "platform_version"
            ] = (
                platform_version_match.group(
                    1
                )
            )

    return server_info


# ============================================================================
# 3. SSH FINGERPRINT
# ============================================================================

def collect_ssh_fingerprint(
    host,
    port=22,
    server_info=None,
    authentication=None,
):
    """
    Build the canonical SSH evidence structure.

    No authentication is performed.
    No vulnerability lookup is performed.

    The resulting structure is intended for consumption by
    PivotRaid's vulnerability and correlation layers.
    """

    fingerprint = {

        # --------------------------------------------------------------------
        # Service
        # --------------------------------------------------------------------

        "service": {

            "name": "ssh",

            "port": port,

            "transport": "tcp",
        },

        # --------------------------------------------------------------------
        # Target
        # --------------------------------------------------------------------

        "target": {

            "host": host,
        },

        # --------------------------------------------------------------------
        # Identification
        # --------------------------------------------------------------------

        "identification": {

            "raw_banner": None,

            "protocol": None,

            "software": None,

            "version": None,

            "platform": None,

            "platform_version": None,
        },

        # --------------------------------------------------------------------
        # Authentication
        # --------------------------------------------------------------------

        "authentication": {

            "authenticated": False,

            "methods": None,

            "enumeration_status": (
                "not_available_without_username"
            ),
        },

        # --------------------------------------------------------------------
        # Negotiation
        # --------------------------------------------------------------------

        "negotiation": {

            "kex": None,

            "cipher": None,

            "mac": None,

            "host_key": None,

            "status": "not_performed",
        },

        # --------------------------------------------------------------------
        # SearchSploit metadata
        # --------------------------------------------------------------------

        "searchsploit": {

            "product": None,

            "version": None,

            "platform": None,

            "queries": [],
        },
    }

    # ========================================================================
    # Identification
    # ========================================================================

    if server_info:

        fingerprint[
            "identification"
        ].update({

            "raw_banner": server_info.get(
                "raw_banner"
            ),

            "protocol": server_info.get(
                "protocol"
            ),

            "software": server_info.get(
                "software"
            ),

            "version": server_info.get(
                "version"
            ),

            "platform": server_info.get(
                "platform"
            ),

            "platform_version": server_info.get(
                "platform_version"
            ),
        })

    # ========================================================================
    # Authentication
    # ========================================================================

    if authentication:

        fingerprint[
            "authentication"
        ].update(
            authentication
        )

    # ========================================================================
    # SearchSploit metadata
    # ========================================================================

    product = fingerprint[
        "identification"
    ][
        "software"
    ]

    version = fingerprint[
        "identification"
    ][
        "version"
    ]

    platform = fingerprint[
        "identification"
    ][
        "platform"
    ]

    fingerprint[
        "searchsploit"
    ][
        "product"
    ] = product

    fingerprint[
        "searchsploit"
    ][
        "version"
    ] = version

    fingerprint[
        "searchsploit"
    ][
        "platform"
    ] = platform

    queries = []

    # ========================================================================
    # Exact Product + Version
    # ========================================================================

    if product and version:

        queries.append({

            "query": (
                f"{product} {version}"
            ),

            "confidence": "HIGH",

            "reason": (
                "exact product and observed version"
            ),
        })

        # --------------------------------------------------------------------
        # Normalized Major.Minor
        # --------------------------------------------------------------------

        major_minor = re.match(
            r"^(\d+\.\d+)",
            version,
        )

        if major_minor:

            normalized_version = (
                major_minor.group(
                    1
                )
            )

            if (
                normalized_version
                != version
            ):

                queries.append({

                    "query": (
                        f"{product} "
                        f"{normalized_version}"
                    ),

                    "confidence": "MEDIUM",

                    "reason": (
                        "normalized product version"
                    ),
                })

    # ========================================================================
    # Product Only
    # ========================================================================

    elif product:

        queries.append({

            "query": product,

            "confidence": "LOW",

            "reason": (
                "product identified but "
                "version unavailable"
            ),
        })

    # ========================================================================
    # Product + Platform
    # ========================================================================

    if product and platform:

        queries.append({

            "query": (
                f"{product} {platform}"
            ),

            "confidence": "LOW",

            "reason": (
                "product and platform identified"
            ),
        })

    fingerprint[
        "searchsploit"
    ][
        "queries"
    ] = queries

    return fingerprint


# ============================================================================
# 4. FINDING HELPER
# ============================================================================

def build_finding(
    title,
    severity="INFO",
    confidence="HIGH",
    category="general",
    evidence=None,
    impact=None,
):
    """
    Build a normalized PivotRaid finding.
    """

    valid_severities = {

        "INFO",

        "LOW",

        "MEDIUM",

        "HIGH",

        "CRITICAL",
    }

    valid_confidence = {

        "LOW",

        "MEDIUM",

        "HIGH",
    }

    severity = str(
        severity or "INFO"
    ).upper()

    confidence = str(
        confidence or "HIGH"
    ).upper()

    if severity not in valid_severities:

        severity = "MEDIUM"

    if confidence not in valid_confidence:

        confidence = "MEDIUM"

    return {

        "title": title,

        "severity": severity,

        "confidence": confidence,

        "category": category,

        "evidence": evidence or {},

        "impact": impact,
    }


# ============================================================================
# 5. JSON SERIALIZATION
# ============================================================================

def parse_ssh_json(
    ssh_fingerprint,
):
    """
    Convert an SSH fingerprint into formatted JSON.
    """

    return json.dumps(
        ssh_fingerprint,
        indent=4,
        sort_keys=False,
    )


# ============================================================================
# 6. SSH SCAN
# ============================================================================

def scan_ssh(
    target,
    port=22,
    timeout=5,
):
    """
    Perform unauthenticated SSH fingerprinting.

    The scanner performs:

        - TCP connection
        - SSH banner collection
        - Banner parsing
        - Structured fingerprint generation
        - SearchSploit query metadata generation

    The scanner does NOT perform:

        - Username enumeration
        - Password authentication
        - Brute force
        - Cryptographic negotiation
        - Exploit execution
        - Global risk scoring
        - Cross-service attack-path generation

    Vulnerability lookup results are intentionally left to the
    centralized vulnerability-enrichment layer.
    """

    start_time = time.time()

    logger.info(
        "Beginning SSH assessment on %s:%s",
        target,
        port,
    )

    # ========================================================================
    # Collect SSH Banner
    # ========================================================================

    banner = get_ssh_banner(
        target,
        port=port,
        timeout=timeout,
    )

    # ========================================================================
    # SSH Not Detected
    # ========================================================================

    if not banner:

        logger.info(
            "SSH service not detected on %s:%s",
            target,
            port,
        )

        return {

            "service": "SSH",

            "port": port,

            "status": "CLOSED",

            "ssh_fingerprint": None,

            "findings": [],

            "vulns": [],

            "impact": [],

            "score": 0,

            "confidence": 0,

            "verdict": "UNKNOWN",

            "scan_time": round(
                time.time()
                - start_time,
                2,
            ),
        }

    # ========================================================================
    # Parse Banner
    # ========================================================================

    server_info = get_ssh_server_info(
        banner
    )

    # ========================================================================
    # Build Fingerprint
    # ========================================================================

    fingerprint = collect_ssh_fingerprint(
        host=target,
        port=port,
        server_info=server_info,
    )

    findings = []

    impact = []

    # ========================================================================
    # Banner Finding
    # ========================================================================

    findings.append(
        build_finding(

            title=(
                "SSH service banner disclosed"
            ),

            severity="INFO",

            confidence="HIGH",

            category="fingerprinting",

            evidence={
                "banner": banner,
            },
        )
    )

    # ========================================================================
    # Software Finding
    # ========================================================================

    software = server_info.get(
        "software"
    )

    version = server_info.get(
        "version"
    )

    if software:

        if version:

            title = (
                f"SSH service fingerprinted as "
                f"{software} {version}"
            )

        else:

            title = (
                f"SSH service fingerprinted as "
                f"{software}"
            )

        findings.append(
            build_finding(

                title=title,

                severity="INFO",

                confidence="HIGH",

                category="fingerprinting",

                evidence={

                    "software": software,

                    "version": version,
                },
            )
        )

    # ========================================================================
    # Platform Finding
    # ========================================================================

    platform = server_info.get(
        "platform"
    )

    platform_version = server_info.get(
        "platform_version"
    )

    if platform:

        if platform_version:

            title = (
                f"SSH platform identified as "
                f"{platform} {platform_version}"
            )

        else:

            title = (
                f"SSH platform identified as "
                f"{platform}"
            )

        findings.append(
            build_finding(

                title=title,

                severity="INFO",

                confidence="HIGH",

                category="fingerprinting",

                evidence={

                    "platform": platform,

                    "platform_version": (
                        platform_version
                    ),
                },
            )
        )

    # ========================================================================
    # Protocol Version Observation
    # ========================================================================

    protocol = server_info.get(
        "protocol"
    )

    if protocol:

        findings.append(
            build_finding(

                title=(
                    f"SSH protocol version identified: "
                    f"{protocol}"
                ),

                severity="INFO",

                confidence="HIGH",

                category="fingerprinting",

                evidence={
                    "protocol": protocol,
                },
            )
        )

    # ========================================================================
    # Negotiation Status
    # ========================================================================

    findings.append(
        build_finding(

            title=(
                "SSH cryptographic negotiation "
                "was not performed"
            ),

            severity="INFO",

            confidence="HIGH",

            category="assessment_scope",

            evidence={

                "negotiation_status": (
                    "not_performed"
                ),

                "method": (
                    "banner_fingerprinting"
                ),
            },
        )
    )

    # ========================================================================
    # SearchSploit Query Metadata
    # ========================================================================

    queries = fingerprint[
        "searchsploit"
    ].get(
        "queries",
        [],
    )

    if queries:

        findings.append(
            build_finding(

                title=(
                    f"Generated {len(queries)} "
                    "vulnerability lookup candidate(s)"
                ),

                severity="INFO",

                confidence="HIGH",

                category="vulnerability_discovery",

                evidence={

                    "queries": queries,

                    "source": "SSH fingerprint",
                },
            )
        )

    # ========================================================================
    # Result
    # ========================================================================

    result = {

        "service": "SSH",

        "port": port,

        "status": "OPEN",

        "ssh_fingerprint": fingerprint,

        "findings": findings,

        # --------------------------------------------------------------------
        # Vulnerability candidates are intentionally empty here.
        #
        # main.py / the central vulnerability layer can enrich this result
        # using the fingerprint.
        # --------------------------------------------------------------------

        "vulns": [],

        "impact": impact,

        # --------------------------------------------------------------------
        # Global risk engine owns these values.
        # --------------------------------------------------------------------

        "score": 0,

        "confidence": 0,

        "verdict": "",

        "scan_time": round(
            time.time()
            - start_time,
            2,
        ),
    }

    logger.info(
        "SSH scan completed on %s in %.2fs",
        target,
        result[
            "scan_time"
        ],
    )

    return result
