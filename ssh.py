import json
import re
import socket


# ============================================================
# 1. RAW SSH BANNER
# ============================================================

def get_ssh_banner(host, port=22, timeout=5):
    """
    Collect the SSH identification banner directly from
    the TCP socket.

    No authentication is performed.
    No username is required.
    No SSH cryptographic negotiation is required.

    Example:

        SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
    """

    sock = None

    try:
        sock = socket.create_connection(
            (host, port),
            timeout=timeout
        )

        sock.settimeout(timeout)

        data = b""

        while len(data) < 4096:

            chunk = sock.recv(1024)

            if not chunk:
                break

            data += chunk

            if b"\n" in data:
                break

        # SSH servers may send pre-banner lines.
        # We specifically look for the SSH identification line.
        for line in data.splitlines():

            line = line.strip()

            if line.startswith(b"SSH-"):

                return line.decode(
                    "utf-8",
                    errors="replace"
                )

        return None

    except (
        socket.timeout,
        OSError
    ):
        return None

    finally:

        if sock is not None:

            try:
                sock.close()

            except OSError:
                pass


# ============================================================
# 2. SSH SERVER INFORMATION
# ============================================================

def get_ssh_server_info(banner):
    """
    Parse the SSH identification banner.

    Produces structured information that can be passed
    to the correlation/SearchSploit engine.
    """

    server_info = {
        "raw_banner": banner,
        "protocol": None,
        "software": None,
        "version": None,
        "platform": None,
        "platform_version": None
    }

    if not banner:
        return server_info

    # ========================================================
    # Protocol Version
    # ========================================================

    protocol_match = re.search(
        r"^SSH-([0-9.]+)-",
        banner
    )

    if protocol_match:

        server_info["protocol"] = (
            protocol_match.group(1)
        )

    # ========================================================
    # Software / Implementation
    # ========================================================

    software_match = re.search(
        r"^SSH-[0-9.]+-([^ ]+)",
        banner
    )

    if software_match:

        software_string = (
            software_match.group(1)
        )

        # ----------------------------------------------------
        # OpenSSH
        #
        # Examples:
        #
        # OpenSSH_4.7p1
        # OpenSSH_8.9p1
        # OpenSSH-9.6p1
        # ----------------------------------------------------

        openssh_match = re.match(
            r"(OpenSSH)[_-]([0-9][A-Za-z0-9._-]*)",
            software_string
        )

        if openssh_match:

            server_info["software"] = (
                openssh_match.group(1)
            )

            server_info["version"] = (
                openssh_match.group(2)
            )

        else:

            # Generic SSH implementation
            server_info["software"] = (
                software_string
            )

    # ========================================================
    # Platform / Distribution
    # ========================================================

    banner_lower = banner.lower()

    platform_patterns = {
        "Ubuntu": r"ubuntu",
        "Debian": r"debian",
        "CentOS": r"centos",
        "RHEL": r"rhel",
        "Fedora": r"fedora",
        "FreeBSD": r"freebsd",
        "OpenBSD": r"openbsd",
        "NetBSD": r"netbsd"
    }

    for platform, pattern in platform_patterns.items():

        if re.search(
            pattern,
            banner_lower
        ):

            server_info["platform"] = platform

            break

    # ========================================================
    # Platform Version / Distribution Suffix
    # ========================================================
    #
    # Example:
    #
    # SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
    #
    # platform      = Debian
    # platform_version = 8ubuntu1
    #
    # We only extract what is explicitly present in the banner.
    # We do not infer an operating-system version.
    # ========================================================

    if server_info["platform"]:

        platform = server_info[
            "platform"
        ]

        platform_version_match = re.search(
            rf"{re.escape(platform)}[-_/]([A-Za-z0-9._-]+)",
            banner,
            re.IGNORECASE
        )

        if platform_version_match:

            server_info["platform_version"] = (
                platform_version_match.group(1)
            )

    return server_info


# ============================================================
# 3. SSH FINGERPRINT
# ============================================================

def collect_ssh_fingerprint(
    host,
    port,
    server_info=None,
    authentication=None
):
    """
    Build the canonical SSH evidence structure.

    This function performs no authentication and no
    vulnerability lookup.

    It prepares the evidence consumed by the
    correlation/SearchSploit engine.
    """

    fingerprint = {

        # ----------------------------------------------------
        # Service
        # ----------------------------------------------------

        "service": {
            "name": "ssh",
            "port": port,
            "transport": "tcp"
        },

        # ----------------------------------------------------
        # Target
        # ----------------------------------------------------

        "target": {
            "host": host
        },

        # ----------------------------------------------------
        # Identification
        # ----------------------------------------------------

        "identification": {
            "raw_banner": None,
            "protocol": None,
            "software": None,
            "version": None,
            "platform": None,
            "platform_version": None
        },

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "authentication": {
            "authenticated": False,
            "methods": None,
            "enumeration_status": (
                "not_available_without_username"
            )
        },

        # ----------------------------------------------------
        # Negotiation
        #
        # These remain null because this scanner intentionally
        # does not perform SSH cryptographic negotiation.
        # ----------------------------------------------------

        "negotiation": {
            "kex": None,
            "cipher": None,
            "mac": None,
            "host_key": None,
            "status": "not_performed"
        },

        # ----------------------------------------------------
        # SearchSploit
        # ----------------------------------------------------

        "searchsploit": {
            "product": None,
            "version": None,
            "platform": None,
            "queries": []
        }
    }

    # ========================================================
    # Identification
    # ========================================================

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
            )
        })

    # ========================================================
    # Authentication
    # ========================================================

    if authentication:

        fingerprint[
            "authentication"
        ].update(
            authentication
        )

    # ========================================================
    # SearchSploit Lookup Metadata
    # ========================================================

    product = fingerprint[
        "identification"
    ]["software"]

    version = fingerprint[
        "identification"
    ]["version"]

    platform = fingerprint[
        "identification"
    ]["platform"]

    fingerprint[
        "searchsploit"
    ]["product"] = product

    fingerprint[
        "searchsploit"
    ]["version"] = version

    fingerprint[
        "searchsploit"
    ]["platform"] = platform

    queries = []

    # --------------------------------------------------------
    # Exact Product + Version
    # --------------------------------------------------------

    if product and version:

        queries.append({
            "query": (
                f"{product} {version}"
            ),

            "confidence": "high",

            "reason": (
                "exact product and observed version"
            )
        })

        # ----------------------------------------------------
        # Normalized Major.Minor
        # ----------------------------------------------------

        major_minor = re.match(
            r"^(\d+\.\d+)",
            version
        )

        if major_minor:

            normalized_version = (
                major_minor.group(1)
            )

            if normalized_version != version:

                queries.append({
                    "query": (
                        f"{product} "
                        f"{normalized_version}"
                    ),

                    "confidence": "medium",

                    "reason": (
                        "normalized product version"
                    )
                })

    # --------------------------------------------------------
    # Product Only
    # --------------------------------------------------------

    elif product:

        queries.append({
            "query": product,

            "confidence": "low",

            "reason": (
                "product identified but "
                "version unavailable"
            )
        })

    # --------------------------------------------------------
    # Product + Platform
    # --------------------------------------------------------

    if product and platform:

        queries.append({
            "query": (
                f"{product} {platform}"
            ),

            "confidence": "low",

            "reason": (
                "product and platform identified"
            )
        })

    fingerprint[
        "searchsploit"
    ]["queries"] = queries

    return fingerprint


# ============================================================
# 4. JSON PARSER
# ============================================================

def parse_ssh_json(ssh_fingerprint):
    """
    Convert the SSH fingerprint into JSON.
    """

    return json.dumps(
        ssh_fingerprint,
        indent=4,
        sort_keys=False
    )


# ============================================================
# 5. SSH SCAN
# ============================================================

def scan_ssh(
    target,
    port=22,
    timeout=5
):
    """
    Perform unauthenticated SSH fingerprinting.

    The scanner performs only TCP-level SSH banner
    identification.

    No username.
    No password.
    No authentication.
    No cryptographic negotiation.
    No exploit execution.

    The resulting fingerprint is designed for the
    SearchSploit correlation engine.
    """

    # ========================================================
    # Collect SSH Banner
    # ========================================================

    banner = get_ssh_banner(
        target,
        port,
        timeout
    )

    # ========================================================
    # Port Closed / SSH Not Detected
    # ========================================================

    if not banner:

        return {
            "service": "SSH",
            "port": port,
            "status": "CLOSED",

            "findings": [],

            "vulns": [],

            "impact": [],

            "attack_path": [],

            "score": 0,

            "confidence": 0,

            "verdict": "UNKNOWN",

            "scan_time": 0
        }

    # ========================================================
    # Parse Banner
    # ========================================================

    server_info = get_ssh_server_info(
        banner
    )

    # ========================================================
    # Build Fingerprint
    # ========================================================

    fingerprint = collect_ssh_fingerprint(
        host=target,
        port=port,
        server_info=server_info
    )

    # ========================================================
    # Findings
    # ========================================================

    findings = []

    findings.append(
        "[INFO] SSH Banner: "
        f"{banner}"
    )

    if server_info.get(
        "software"
    ):

        software = server_info[
            "software"
        ]

        version = server_info.get(
            "version"
        )

        if version:

            findings.append(
                "[INFO] Fingerprinted: "
                f"{software} {version}"
            )

        else:

            findings.append(
                "[INFO] Fingerprinted: "
                f"{software}"
            )

    if server_info.get(
        "platform"
    ):

        platform = server_info[
            "platform"
        ]

        platform_version = server_info.get(
            "platform_version"
        )

        if platform_version:

            findings.append(
                "[INFO] Platform: "
                f"{platform} {platform_version}"
            )

        else:

            findings.append(
                "[INFO] Platform: "
                f"{platform}"
            )

    findings.append(
        "[INFO] SSH cryptographic negotiation "
        "not performed; banner fingerprint used."
    )

    # ========================================================
    # Return PivotRaid-Compatible Result
    # ========================================================

    return {
        "service": "SSH",

        "port": port,

        "status": "OPEN",

        "ssh_fingerprint": fingerprint,

        "findings": findings,

        "vulns": [],

        "impact": [],

        "attack_path": [],

        "score": 0,

        "confidence": 0,

        "verdict": "INFO",

        "scan_time": 0
    }
