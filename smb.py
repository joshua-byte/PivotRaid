import time
import logging

from impacket.smbconnection import SMBConnection


# ============================================================================
# Local vulnerability engine
# ============================================================================

try:
    from vulnerabilities import query_searchsploit
except ImportError:

    def query_searchsploit(
        software,
        version,
    ):
        return []


logger = logging.getLogger("PivotRaid.SMB")


# ============================================================================
# SMB Scanner
# ============================================================================

class SMBScanner:
    """
    SMB-specific security assessment module.

    Responsibilities:
        - Establish SMB connection
        - Identify SMB dialect
        - Check signing enforcement
        - Audit null sessions / weak credentials
        - Enumerate shares
        - Test share accessibility
        - Perform bounded file enumeration
        - Classify potentially sensitive files
        - Collect structured evidence
        - Identify vulnerability candidates

    This module does NOT:
        - Calculate global risk
        - Generate cross-service attack paths
        - Execute exploits
        - Perform unrestricted brute-force operations

    Global scoring and correlation are handled by the central
    PivotRaid risk/correlation layers.

    IMPORTANT
    ---------
    SearchSploit results are vulnerability CANDIDATES.

    They are stored in result["vulns"] and are NOT converted into
    independent HIGH/CRITICAL findings.

    This prevents vulnerability lookup results from being counted
    twice by the central risk engine.
    """

    # ========================================================================
    # Initialization
    # ========================================================================

    def __init__(
        self,
        target,
        timeout=5,
    ):

        self.target = target

        self.timeout = timeout

        self.conn = None

        self.result = {

            # ----------------------------------------------------------------
            # Service identity
            # ----------------------------------------------------------------

            "service": "SMB",

            "port": 445,

            "status": "CLOSED",

            # ----------------------------------------------------------------
            # Structured findings
            # ----------------------------------------------------------------

            "findings": [],

            # ----------------------------------------------------------------
            # Evidence
            # ----------------------------------------------------------------

            "evidence": {
                "dialect": None,
                "dialect_name": None,
                "signing_required": None,
                "shares": [],
                "sample_files": [],
            },

            # ----------------------------------------------------------------
            # Authentication
            # ----------------------------------------------------------------

            "anonymous": False,

            "weak_creds": None,

            # ----------------------------------------------------------------
            # Share exposure
            # ----------------------------------------------------------------

            "shares": [],

            "accessible_shares": [],

            # ----------------------------------------------------------------
            # File classification
            # ----------------------------------------------------------------

            "file_count": 0,

            "classified_hits": {},

            # ----------------------------------------------------------------
            # Vulnerability candidates
            # ----------------------------------------------------------------

            "vulns": [],

            # ----------------------------------------------------------------
            # Timing
            # ----------------------------------------------------------------

            "scan_time": 0,

            # ----------------------------------------------------------------
            # Compatibility fields
            #
            # Global risk scoring and attack paths are handled elsewhere.
            # ----------------------------------------------------------------

            "impact": [],

            "score": 0,

            "confidence": 0,

            "verdict": "",

        }

    # ========================================================================
    # Finding helper
    # ========================================================================

    def add_finding(
        self,
        title,
        severity="INFO",
        confidence="HIGH",
        category="general",
        evidence=None,
        impact=None,
    ):
        """
        Add a normalized finding to the assessment.

        Severity:
            INFO / LOW / MEDIUM / HIGH / CRITICAL

        Confidence:
            LOW / MEDIUM / HIGH

        Findings represent observed conditions.

        Vulnerability candidates belong in result["vulns"].
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

        finding = {
            "title": title,

            "severity": severity,

            "confidence": confidence,

            "category": category,

            "evidence": evidence or {},
        }

        self.result[
            "findings"
        ].append(
            finding
        )

        if impact:

            self.result[
                "impact"
            ].append(
                impact
            )

        logger.debug(
            "SMB finding: [%s] %s",
            severity,
            title,
        )

    # ========================================================================
    # Layer 1: SMB connection
    # ========================================================================

    def establish_connection(
        self,
    ):
        """
        Establish an SMB connection and allow Impacket to negotiate
        the protocol dialect.
        """

        try:

            self.conn = SMBConnection(
                self.target,
                self.target,
                sess_port=445,
                timeout=self.timeout,
            )

            self.result[
                "status"
            ] = "OPEN"

            self.add_finding(
                title=(
                    "SMB service is accessible"
                ),
                severity="INFO",
                confidence="HIGH",
                category="availability",
                evidence={
                    "target": self.target,
                    "port": 445,
                },
            )

            return True

        except Exception as exc:

            logger.debug(
                "SMB connection failed to %s:445 - %s",
                self.target,
                exc,
            )

            self.add_finding(
                title=(
                    "SMB service is not accessible"
                ),
                severity="INFO",
                confidence="HIGH",
                category="availability",
                evidence={
                    "target": self.target,
                    "port": 445,
                    "error": str(exc),
                },
            )

            return False

    # ========================================================================
    # Layer 2: Protocol properties
    # ========================================================================

    def analyze_protocol_properties(
        self,
    ):
        """
        Inspect SMB signing requirements and negotiated dialect.
        """

        if not self.conn:
            return

        # ====================================================================
        # SMB signing
        # ====================================================================

        try:

            signing_required = (
                self.conn.isSigningRequired()
            )

            self.result[
                "evidence"
            ][
                "signing_required"
            ] = bool(
                signing_required
            )

            if signing_required:

                self.add_finding(
                    title=(
                        "SMB signing is required"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="protocol_security",
                    evidence={
                        "signing_required": True,
                    },
                )

            else:

                self.add_finding(
                    title=(
                        "SMB signing is not required"
                    ),
                    severity="HIGH",
                    confidence="HIGH",
                    category="protocol_security",
                    evidence={
                        "signing_required": False,
                    },
                    impact=(
                        "Lack of mandatory SMB signing may increase "
                        "exposure to authentication-relay attacks "
                        "depending on the surrounding network configuration."
                    ),
                )

        except Exception as exc:

            logger.debug(
                "Unable to determine SMB signing state: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "SMB signing requirement "
                    "could not be determined"
                ),
                severity="INFO",
                confidence="LOW",
                category="protocol_security",
                evidence={
                    "error": str(exc),
                },
            )

        # ====================================================================
        # SMB dialect
        # ====================================================================

        try:

            dialect = self.conn.getDialect()

            dialect_map = {
                0x0100: "SMBv1 (NT LM 0.12)",
                0x0202: "SMB 2.0.2",
                0x0210: "SMB 2.1",
                0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2",
                0x0311: "SMB 3.1.1",
            }

            dialect_name = dialect_map.get(
                dialect,
                f"Unknown (0x{dialect:X})",
            )

            self.result[
                "evidence"
            ][
                "dialect"
            ] = dialect

            self.result[
                "evidence"
            ][
                "dialect_name"
            ] = dialect_name

            self.add_finding(
                title=(
                    f"Negotiated SMB dialect: "
                    f"{dialect_name}"
                ),
                severity="INFO",
                confidence="HIGH",
                category="fingerprinting",
                evidence={
                    "dialect": dialect,
                    "dialect_name": dialect_name,
                },
            )

            # ------------------------------------------------------------
            # SMBv1
            # ------------------------------------------------------------

            if dialect == 0x0100:

                self.add_finding(
                    title=(
                        "Deprecated SMBv1 protocol detected"
                    ),
                    severity="HIGH",
                    confidence="HIGH",
                    category="protocol_security",
                    evidence={
                        "dialect": "SMBv1",
                        "dialect_code": dialect,
                    },
                    impact=(
                        "SMBv1 is an obsolete protocol with a history "
                        "of serious security vulnerabilities."
                    ),
                )

                # --------------------------------------------------------
                # SearchSploit lookup
                #
                # Results are candidates only.
                # --------------------------------------------------------

                try:

                    exploits = query_searchsploit(
                        "SMBv1",
                        "",
                    )

                except Exception as exc:

                    exploits = []

                    logger.debug(
                        "SMBv1 SearchSploit query failed: %s",
                        exc,
                    )

                self._record_vulnerability_candidates(
                    exploits,
                    software="SMBv1",
                    version="",
                )

        except Exception as exc:

            logger.debug(
                "SMB dialect retrieval failed: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "SMB dialect could not be determined"
                ),
                severity="INFO",
                confidence="LOW",
                category="fingerprinting",
                evidence={
                    "error": str(exc),
                },
            )

    # ========================================================================
    # Vulnerability normalization
    # ========================================================================

    def _record_vulnerability_candidates(
        self,
        exploits,
        software=None,
        version=None,
    ):
        """
        Store vulnerability candidates without treating them as
        confirmed vulnerabilities or duplicating them as risk findings.

        SearchSploit output belongs exclusively in result["vulns"].

        A vulnerability candidate is not itself an observed security
        condition. The central risk engine may consider candidates as
        contextual evidence, but they must not be converted into
        independent HIGH/CRITICAL findings here.
        """

        if not exploits:
            return

        # --------------------------------------------------------------------
        # Store candidates.
        # --------------------------------------------------------------------

        self.result[
            "vulns"
        ].extend(
            exploits
        )

        # --------------------------------------------------------------------
        # Add one informational discovery finding.
        #
        # INFO contributes zero risk in the central risk engine.
        # --------------------------------------------------------------------

        self.add_finding(
            title=(
                "SearchSploit identified "
                f"{len(exploits)} vulnerability candidate(s)"
            ),
            severity="INFO",
            confidence="HIGH",
            category="vulnerability_discovery",
            evidence={
                "software": software,
                "version": version,
                "candidate_count": len(exploits),
                "source": (
                    "Exploit-DB/SearchSploit"
                ),
            },
        )

        logger.info(
            "SMB SearchSploit identified %d "
            "vulnerability candidate(s) for %s %s",
            len(exploits),
            software or "",
            version or "",
        )

    # ========================================================================
    # Layer 3: Authentication auditing
    # ========================================================================

    def audit_authentication(
        self,
    ):
        """
        Test null-session access and a very small set of common
        credential pairs.

        This is deliberately a limited audit and not a brute-force
        mechanism.
        """

        if not self.conn:
            return

        # ====================================================================
        # Null session
        # ====================================================================

        try:

            self.conn.login(
                "",
                "",
            )

            self.result[
                "anonymous"
            ] = True

            self.add_finding(
                title=(
                    "SMB null session accepted"
                ),
                severity="HIGH",
                confidence="HIGH",
                category="authentication",
                evidence={
                    "username": "",
                    "authentication": "successful",
                },
                impact=(
                    "Unauthenticated SMB sessions may permit access "
                    "to information or shares depending on server policy."
                ),
            )

            return

        except Exception as exc:

            logger.debug(
                "SMB null session rejected: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "SMB null session rejected"
                ),
                severity="INFO",
                confidence="HIGH",
                category="authentication",
                evidence={
                    "authentication": (
                        "null session denied"
                    ),
                },
            )

        # ====================================================================
        # Controlled weak credential checks
        # ====================================================================

        weak_pairs = [
            ("guest", ""),
            ("admin", "admin"),
            ("administrator", "password"),
            ("user", "password"),
        ]

        for username, password in weak_pairs:

            test_conn = None

            try:

                test_conn = SMBConnection(
                    self.target,
                    self.target,
                    sess_port=445,
                    timeout=self.timeout,
                )

                test_conn.login(
                    username,
                    password,
                )

                self.result[
                    "weak_creds"
                ] = {
                    "username": username,
                    "password": password,
                }

                self.add_finding(
                    title=(
                        "Common weak SMB credentials accepted"
                    ),
                    severity="CRITICAL",
                    confidence="HIGH",
                    category="authentication",
                    evidence={
                        "username": username,
                        "credential_test": "successful",
                    },
                    impact=(
                        "The tested credential pair provides "
                        "authenticated SMB access."
                    ),
                )

                logger.info(
                    "Weak SMB credentials validated for %s",
                    self.target,
                )

                return

            except Exception as exc:

                logger.debug(
                    "SMB credential pair rejected for %s: %s",
                    username,
                    exc,
                )

            finally:

                if test_conn:

                    try:
                        test_conn.close()

                    except Exception:
                        pass

    # ========================================================================
    # Layer 4: Share enumeration
    # ========================================================================

    def enumerate_shares(
        self,
    ):
        """
        Enumerate SMB shares visible to the current session.
        """

        if not self.conn:
            return []

        try:

            shares = self.conn.listShares()

            share_names = []

            for share in shares:

                try:

                    name = (
                        share[
                            "shi1_netname"
                        ]
                        .strip("\x00")
                        .strip()
                    )

                    if name:
                        share_names.append(
                            name
                        )

                except Exception:
                    continue

            self.result[
                "shares"
            ] = share_names

            self.result[
                "evidence"
            ][
                "shares"
            ] = share_names

            normal = [
                name
                for name in share_names
                if not name.endswith("$")
            ]

            hidden = [
                name
                for name in share_names
                if name.endswith("$")
            ]

            if normal:

                self.add_finding(
                    title=(
                        "SMB shares enumerated"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="enumeration",
                    evidence={
                        "shares": normal,
                        "count": len(normal),
                    },
                )

            if hidden:

                self.add_finding(
                    title=(
                        "Administrative SMB shares enumerated"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="enumeration",
                    evidence={
                        "shares": hidden,
                        "count": len(hidden),
                    },
                )

            return share_names

        except Exception as exc:

            logger.debug(
                "SMB share enumeration failed: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "SMB share enumeration failed"
                ),
                severity="INFO",
                confidence="HIGH",
                category="enumeration",
                evidence={
                    "error": str(exc),
                },
            )

            return []

    # ========================================================================
    # Layer 4b: Share access
    # ========================================================================

    def analyze_share_access(
        self,
        shares,
    ):
        """
        Test whether the current SMB session can list the root of
        each discovered share.
        """

        if not self.conn or not shares:
            return []

        accessible = []

        for share in shares:

            try:

                files = self.conn.listPath(
                    share,
                    "*",
                )

                accessible.append(
                    share
                )

                self.add_finding(
                    title=(
                        f"SMB share is readable: "
                        f"{share}"
                    ),
                    severity="HIGH",
                    confidence="HIGH",
                    category="authorization",
                    evidence={
                        "share": share,
                        "root_listing_entries": len(
                            files
                        ),
                    },
                    impact=(
                        "The current SMB authentication context can "
                        "enumerate content within this share."
                    ),
                )

            except Exception as exc:

                logger.debug(
                    "Unable to access SMB share %s: %s",
                    share,
                    exc,
                )

        self.result[
            "accessible_shares"
        ] = accessible

        if accessible:

            self.result[
                "evidence"
            ][
                "shares"
            ] = accessible

        return accessible

    # ========================================================================
    # Layer 5: Bounded recursive file enumeration
    # ========================================================================

    def list_files_safely(
        self,
        share,
        path="*",
        depth=1,
    ):
        """
        Perform bounded SMB file enumeration.

        The scanner deliberately limits recursion to prevent excessive
        enumeration and problematic Windows system directories.
        """

        if not self.conn:
            return []

        if depth < 0:
            return []

        collected = []

        blacklist = {
            ".",
            "..",
            "system volume information",
            "$recycle.bin",
        }

        try:

            entries = self.conn.listPath(
                share,
                path,
            )

        except Exception as exc:

            logger.debug(
                "SMB listing failed for %s/%s: %s",
                share,
                path,
                exc,
            )

            return collected

        for entry in entries:

            try:

                name = (
                    entry
                    .get_filename()
                    .strip()
                )

            except Exception:
                continue

            if not name:
                continue

            if name.lower() in blacklist:
                continue

            try:

                if entry.is_directory():

                    if depth > 0:

                        base_path = (
                            path.rstrip("*")
                        )

                        if not base_path.endswith("\\"):
                            base_path += "\\"

                        sub_path = (
                            f"{base_path}"
                            f"{name}"
                            f"\\*"
                        )

                        collected.extend(
                            self.list_files_safely(
                                share,
                                sub_path,
                                depth - 1,
                            )
                        )

                else:

                    relative_path = (
                        f"{path.rstrip('*').rstrip(chr(92))}"
                        f"\\{name}"
                    )

                    collected.append(
                        relative_path.strip("\\")
                    )

            except Exception as exc:

                logger.debug(
                    "SMB entry processing failed "
                    "for %s/%s: %s",
                    share,
                    name,
                    exc,
                )

        return collected

    # ========================================================================
    # Layer 6: File classification
    # ========================================================================

    def classify_discovered_files(
        self,
        files,
    ):
        """
        Classify discovered filenames using conservative heuristics.

        A filename match is treated as an indicator, not proof that
        the underlying file contains sensitive information.
        """

        categories = {

            "credentials": [
                ".env",
                "passwd",
                "shadow",
                "id_rsa",
                "unattend.xml",
                "web.config",
            ],

            "configs": [
                ".conf",
                ".ini",
                ".cfg",
                "config",
                "settings.json",
            ],

            "databases": [
                ".sql",
                ".db",
                ".sqlite",
                ".bak",
            ],

            "backups": [
                ".zip",
                ".tar",
                ".gz",
                "backup",
            ],
        }

        hits = {
            category: []
            for category in categories
        }

        self.result[
            "file_count"
        ] = len(
            files
        )

        for file_path in files:

            lowered = file_path.lower()

            for category, keywords in categories.items():

                if any(
                    keyword in lowered
                    for keyword in keywords
                ):

                    hits[
                        category
                    ].append(
                        file_path
                    )

        self.result[
            "classified_hits"
        ] = hits

        # ====================================================================
        # Credential-bearing files
        # ====================================================================

        if hits[
            "credentials"
        ]:

            self.add_finding(
                title=(
                    "Potential credential-bearing "
                    "files exposed"
                ),
                severity="CRITICAL",
                confidence="MEDIUM",
                category="file_exposure",
                evidence={
                    "files": (
                        hits[
                            "credentials"
                        ][:25]
                    ),
                    "classification": (
                        "filename-based heuristic"
                    ),
                },
                impact=(
                    "Accessible credential-related files may expose "
                    "passwords, secrets, private keys, or configuration "
                    "credentials."
                ),
            )

        # ====================================================================
        # Database files
        # ====================================================================

        if hits[
            "databases"
        ]:

            self.add_finding(
                title=(
                    "Potential database files exposed"
                ),
                severity="HIGH",
                confidence="MEDIUM",
                category="file_exposure",
                evidence={
                    "files": (
                        hits[
                            "databases"
                        ][:25]
                    ),
                    "classification": (
                        "filename-based heuristic"
                    ),
                },
                impact=(
                    "Accessible database files may contain sensitive "
                    "application or operational data."
                ),
            )

        # ====================================================================
        # Backup archives
        # ====================================================================

        if hits[
            "backups"
        ]:

            self.add_finding(
                title=(
                    "Potential backup archives exposed"
                ),
                severity="HIGH",
                confidence="MEDIUM",
                category="file_exposure",
                evidence={
                    "files": (
                        hits[
                            "backups"
                        ][:25]
                    ),
                    "classification": (
                        "filename-based heuristic"
                    ),
                },
            )

        # ====================================================================
        # Configuration files
        # ====================================================================

        if hits[
            "configs"
        ]:

            self.add_finding(
                title=(
                    "Potential configuration files exposed"
                ),
                severity="MEDIUM",
                confidence="MEDIUM",
                category="file_exposure",
                evidence={
                    "files": (
                        hits[
                            "configs"
                        ][:25]
                    ),
                    "classification": (
                        "filename-based heuristic"
                    ),
                },
            )

    # ========================================================================
    # Connection cleanup
    # ========================================================================

    def close(
        self,
    ):
        """
        Safely close the SMB connection.
        """

        if not self.conn:
            return

        try:

            self.conn.close()

        except Exception as exc:

            logger.debug(
                "SMB connection cleanup failed: %s",
                exc,
            )

        finally:

            self.conn = None

    # ========================================================================
    # Finalization
    # ========================================================================

    def _finalize(
        self,
        start_time,
    ):
        """
        Finalize timing information.

        Global risk scoring and attack-path generation intentionally
        remain outside this module.
        """

        self.result[
            "scan_time"
        ] = round(
            time.time()
            - start_time,
            2,
        )

        # --------------------------------------------------------------------
        # Compatibility fields.
        #
        # The central risk engine owns these values.
        # --------------------------------------------------------------------

        self.result[
            "score"
        ] = 0

        self.result[
            "confidence"
        ] = 0

        self.result[
            "verdict"
        ] = ""

        logger.info(
            "SMB scan completed on %s in %.2fs",
            self.target,
            self.result[
                "scan_time"
            ],
        )

        return self.result

    # ========================================================================
    # Orchestrator
    # ========================================================================

    def execute_scan(
        self,
    ):
        """
        Execute the SMB assessment in a controlled sequence.
        """

        start_time = time.time()

        logger.info(
            "Initiating SMB security assessment on %s:445",
            self.target,
        )

        try:

            # ================================================================
            # Connection
            # ================================================================

            if not self.establish_connection():

                return self._finalize(
                    start_time
                )

            # ================================================================
            # Protocol analysis
            # ================================================================

            self.analyze_protocol_properties()

            # ================================================================
            # Authentication
            # ================================================================

            self.audit_authentication()

            # ================================================================
            # Shares
            # ================================================================

            shares = self.enumerate_shares()

            accessible = (
                self.analyze_share_access(
                    shares
                )
            )

            # ================================================================
            # Bounded file enumeration
            # ================================================================

            discovered_files = []

            # Deliberately limit the number of shares crawled.
            for share in accessible[:2]:

                files = (
                    self.list_files_safely(
                        share,
                        depth=1,
                    )
                )

                discovered_files.extend(
                    files
                )

            if discovered_files:

                self.result[
                    "evidence"
                ][
                    "sample_files"
                ] = (
                    discovered_files[:15]
                )

                self.add_finding(
                    title=(
                        "SMB file enumeration "
                        "discovered "
                        f"{len(discovered_files)} entries"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="enumeration",
                    evidence={
                        "file_count": len(
                            discovered_files
                        ),
                        "sample_files": (
                            discovered_files[:15]
                        ),
                    },
                )

                self.classify_discovered_files(
                    discovered_files
                )

        except Exception as exc:

            logger.critical(
                "SMB scanner runtime failure: %s",
                exc,
                exc_info=True,
            )

            self.add_finding(
                title=(
                    "SMB scan terminated unexpectedly"
                ),
                severity="MEDIUM",
                confidence="HIGH",
                category="scanner_error",
                evidence={
                    "error": str(exc),
                },
            )

        finally:

            self.close()

        return self._finalize(
            start_time
        )


# ============================================================================
# Standardized interface for main.py
# ============================================================================

def scan_smb(
    target,
    timeout=5,
):
    """
    Standard PivotRaid SMB scanner interface.
    """

    scanner = SMBScanner(
        target=target,
        timeout=timeout,
    )

    return scanner.execute_scan()
