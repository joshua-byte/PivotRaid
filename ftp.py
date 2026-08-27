import io
import re
import time
import logging

from ftplib import FTP, error_perm, error_temp

from vulnerabilities import query_searchsploit


logger = logging.getLogger("PivotRaid.FTP")


# ============================================================================
# FTP Scanner
# ============================================================================

class FTPScanner:
    """
    FTP-specific security assessment module.

    Responsibilities
    ----------------

    - Establish FTP connection
    - Fingerprint FTP service
    - Audit anonymous / weak authentication
    - Enumerate accessible files
    - Classify potentially sensitive files
    - Verify write permissions
    - Discover vulnerability candidates
    - Collect structured evidence

    This module deliberately does NOT:

    - calculate global risk
    - calculate a service risk score
    - determine exploitability
    - construct cross-service attack paths

    Those responsibilities belong to the central intelligence engines.
    """

    # ========================================================================
    # Initialization
    # ========================================================================

    def __init__(
        self,
        target,
        port=21,
        timeout=5,
    ):

        self.target = target
        self.port = port
        self.timeout = timeout

        self.ftp = None

        self.result = {

            # ----------------------------------------------------------------
            # Service identity
            # ----------------------------------------------------------------

            "service": "FTP",

            "port": port,

            "status": "CLOSED",

            # ----------------------------------------------------------------
            # Structured findings
            # ----------------------------------------------------------------

            "findings": [],

            # ----------------------------------------------------------------
            # Evidence
            # ----------------------------------------------------------------

            "evidence": {
                "banner": "",
                "software": None,
                "version": None,
                "sample_files": [],
            },

            # ----------------------------------------------------------------
            # Explicit fingerprint
            #
            # This gives the rest of PivotRaid a consistent representation
            # of the observed FTP service.
            # ----------------------------------------------------------------

            "ftp_fingerprint": {
                "service": {
                    "name": "ftp",
                },

                "identification": {
                    "software": None,
                    "version": None,
                    "platform": None,
                },
            },

            # ----------------------------------------------------------------
            # Authentication
            # ----------------------------------------------------------------

            "anonymous": False,

            "weak_creds": None,

            # ----------------------------------------------------------------
            # File-system exposure
            # ----------------------------------------------------------------

            "writable": False,

            "file_count": 0,

            "classified_hits": {},

            # ----------------------------------------------------------------
            # Vulnerability candidates
            #
            # IMPORTANT:
            # SearchSploit candidates live here.
            # They are NOT duplicated into findings[].
            # ----------------------------------------------------------------

            "vulns": [],

            # ----------------------------------------------------------------
            # Timing
            # ----------------------------------------------------------------

            "scan_time": 0,

            # ----------------------------------------------------------------
            # Legacy compatibility fields
            #
            # These are retained temporarily because older report code may
            # still expect them, but they are deliberately not calculated
            # by this scanner.
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
        Add a structured observation.

        Findings represent observations made by the scanner.

        Vulnerability candidates belong in result["vulns"] and should
        not be duplicated here.
        """

        finding = {

            "title": title,

            "severity": str(
                severity
            ).upper(),

            "confidence": str(
                confidence
            ).upper(),

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
            "Finding added: [%s] %s",
            finding["severity"],
            title,
        )

    # ========================================================================
    # Service fingerprinting
    # ========================================================================

    def extract_version_from_banner(
        self,
        banner,
    ):
        """
        Extract a software name and version from an FTP banner.

        Example:

            220 (vsFTPd 2.3.4)

        Returns:

            ("vsftpd", "2.3.4")

        or:

            (None, None)
        """

        if not banner:
            return None, None

        match = re.search(
            r"\b([A-Za-z][A-Za-z0-9._-]*)"
            r"\s+v?(\d+(?:\.\d+){1,4})\b",
            banner,
        )

        if not match:
            return None, None

        software = match.group(
            1
        ).strip().lower()

        version = match.group(
            2
        ).strip()

        return software, version

    # ========================================================================
    # Fingerprint service
    # ========================================================================

    def finger_print_service(
        self,
    ):
        """
        Establish an FTP connection and collect service identity evidence.
        """

        try:

            self.ftp = FTP()

            self.ftp.connect(
                self.target,
                self.port,
                timeout=self.timeout,
            )

            self.result[
                "status"
            ] = "OPEN"

            # ------------------------------------------------------------
            # Banner
            # ------------------------------------------------------------

            try:

                banner = (
                    self.ftp.getwelcome()
                    or ""
                )

                banner = banner.strip()

                self.result[
                    "evidence"
                ][
                    "banner"
                ] = banner

                self.add_finding(
                    title=(
                        "FTP service banner disclosed"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="fingerprinting",
                    evidence={
                        "banner": banner,
                    },
                )

                # --------------------------------------------------------
                # Software/version
                # --------------------------------------------------------

                software, version = (
                    self.extract_version_from_banner(
                        banner
                    )
                )

                if software:

                    self.result[
                        "evidence"
                    ][
                        "software"
                    ] = software

                    self.result[
                        "evidence"
                    ][
                        "version"
                    ] = version

                    # Update structured fingerprint.
                    self.result[
                        "ftp_fingerprint"
                    ][
                        "identification"
                    ][
                        "software"
                    ] = software

                    self.result[
                        "ftp_fingerprint"
                    ][
                        "identification"
                    ][
                        "version"
                    ] = version

                    self.add_finding(
                        title=(
                            f"FTP service fingerprinted "
                            f"as {software} {version}"
                        ),
                        severity="INFO",
                        confidence="HIGH",
                        category="fingerprinting",
                        evidence={
                            "software": software,
                            "version": version,
                            "banner": banner,
                        },
                    )

                    # ----------------------------------------------------
                    # SearchSploit vulnerability discovery
                    #
                    # IMPORTANT:
                    #
                    # We store the results in vulns[] only.
                    #
                    # We do NOT create a CRITICAL/HIGH finding for every
                    # SearchSploit result.
                    # ----------------------------------------------------

                    try:

                        exploits = query_searchsploit(
                            software,
                            version,
                        )

                    except Exception as exc:

                        logger.warning(
                            "SearchSploit query failed "
                            "for %s %s: %s",
                            software,
                            version,
                            exc,
                        )

                        exploits = []

                    if exploits:

                        self.result[
                            "vulns"
                        ].extend(
                            exploits
                        )

                        logger.info(
                            "FTP SearchSploit lookup "
                            "identified %d candidate(s) "
                            "for %s %s",
                            len(exploits),
                            software,
                            version,
                        )

                        # One informational finding summarises the lookup.
                        #
                        # This contributes ZERO risk because it is INFO.
                        self.add_finding(
                            title=(
                                "SearchSploit identified "
                                f"{len(exploits)} vulnerability "
                                "candidate(s)"
                            ),
                            severity="INFO",
                            confidence="HIGH",
                            category=(
                                "vulnerability_discovery"
                            ),
                            evidence={
                                "software": software,
                                "version": version,
                                "candidate_count": len(
                                    exploits
                                ),
                                "source": (
                                    "Exploit-DB/SearchSploit"
                                ),
                            },
                        )

                    else:

                        logger.info(
                            "No SearchSploit candidates "
                            "identified for %s %s",
                            software,
                            version,
                        )

                        self.add_finding(
                            title=(
                                "No SearchSploit vulnerability "
                                "candidates identified"
                            ),
                            severity="INFO",
                            confidence="MEDIUM",
                            category=(
                                "vulnerability_discovery"
                            ),
                            evidence={
                                "software": software,
                                "version": version,
                                "candidate_count": 0,
                                "source": (
                                    "Exploit-DB/SearchSploit"
                                ),
                            },
                        )

            except Exception as exc:

                logger.debug(
                    "FTP banner extraction failed: %s",
                    exc,
                )

                self.add_finding(
                    title=(
                        "FTP banner could not be "
                        "reliably extracted"
                    ),
                    severity="INFO",
                    confidence="LOW",
                    category="fingerprinting",
                    evidence={
                        "error": str(exc),
                    },
                )

            return True

        except Exception as exc:

            logger.warning(
                "Failed to connect to FTP on %s:%s - %s",
                self.target,
                self.port,
                exc,
            )

            self.add_finding(
                title=(
                    "FTP service connection failed"
                ),
                severity="INFO",
                confidence="HIGH",
                category="availability",
                evidence={
                    "target": self.target,
                    "port": self.port,
                    "error": str(exc),
                },
            )

            return False

    # ========================================================================
    # Authentication audit
    # ========================================================================

    def audit_authentication(
        self,
    ):
        """
        Safely checks anonymous authentication.

        This is not a brute-force mechanism.
        """

        if (
            self.result["status"]
            != "OPEN"
            or not self.ftp
        ):
            return

        # --------------------------------------------------------------------
        # Anonymous authentication
        # --------------------------------------------------------------------

        try:

            self.ftp.login(
                "anonymous",
                "anonymous@test.com",
            )

            self.result[
                "anonymous"
            ] = True

            self.add_finding(
                title=(
                    "Anonymous FTP authentication "
                    "is permitted"
                ),
                severity="HIGH",
                confidence="HIGH",
                category="authentication",
                evidence={
                    "username": "anonymous",
                    "authentication": "successful",
                },
                impact=(
                    "Unauthenticated network users may gain "
                    "access to the FTP service."
                ),
            )

            return

        except (
            error_perm,
            error_temp,
        ) as exc:

            logger.debug(
                "Anonymous FTP login denied: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "Anonymous FTP authentication "
                    "is disabled"
                ),
                severity="INFO",
                confidence="HIGH",
                category="authentication",
                evidence={
                    "authentication": (
                        "anonymous denied"
                    ),
                },
            )

        except Exception as exc:

            logger.debug(
                "Anonymous authentication check failed: %s",
                exc,
            )

    # ========================================================================
    # Controlled weak credential check
    # ========================================================================

    def audit_weak_credentials(
        self,
    ):
        """
        Performs a small, fixed credential audit.

        This is intentionally limited and should not become unrestricted
        password spraying or brute-force behavior.
        """

        if (
            self.result["status"]
            != "OPEN"
        ):
            return

        weak_pairs = [
            ("ftp", "ftp"),
            ("admin", "admin"),
            ("user", "password"),
            ("root", "root"),
        ]

        for username, password in weak_pairs:

            session = None

            try:

                session = FTP()

                session.connect(
                    self.target,
                    self.port,
                    timeout=self.timeout,
                )

                session.login(
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
                        "Common weak FTP credentials accepted"
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
                        "authenticated FTP access."
                    ),
                )

                logger.info(
                    "Weak FTP credentials validated for %s",
                    self.target,
                )

                return

            except (
                error_perm,
                error_temp,
            ):

                continue

            except Exception as exc:

                logger.debug(
                    "Weak credential audit stopped: %s",
                    exc,
                )

                return

            finally:

                if session:

                    try:

                        session.quit()

                    except Exception:

                        try:
                            session.close()

                        except Exception:
                            pass

    # ========================================================================
    # FTP file enumeration
    # ========================================================================

    def list_files_safely(
        self,
        path="",
        depth=2,
        visited=None,
    ):
        """
        Enumerate accessible FTP files with bounded recursion.
        """

        if visited is None:
            visited = set()

        if depth < 0:
            return []

        collected = []

        normalized_path = (
            path
            or "/"
        )

        if normalized_path in visited:
            return collected

        visited.add(
            normalized_path
        )

        try:

            if path:

                self.ftp.cwd(
                    path
                )

            else:

                self.ftp.cwd(
                    "/"
                )

            items = self.ftp.nlst()

        except Exception as exc:

            logger.debug(
                "FTP enumeration failed at '%s': %s",
                path,
                exc,
            )

            return collected

        for item in items:

            if (
                not item
                or item.strip()
                in {
                    ".",
                    "..",
                }
            ):
                continue

            item = item.strip()

            try:

                current_directory = (
                    self.ftp.pwd()
                )

                # --------------------------------------------------------
                # Test whether item is a directory.
                # --------------------------------------------------------

                self.ftp.cwd(
                    item
                )

                child_path = (
                    f"{current_directory.rstrip('/')}"
                    f"/{item}"
                )

                collected.extend(
                    self.list_files_safely(
                        child_path,
                        depth=depth - 1,
                        visited=visited,
                    )
                )

                self.ftp.cwd(
                    current_directory
                )

            except (
                error_perm,
                error_temp,
            ):

                file_path = (
                    f"{path.rstrip('/')}/{item}"
                    if path
                    else item
                )

                collected.append(
                    file_path.strip("/")
                )

                try:

                    self.ftp.cwd(
                        "/"
                    )

                    if path:
                        self.ftp.cwd(
                            path
                        )

                except Exception:
                    pass

            except Exception as exc:

                logger.debug(
                    "FTP item inspection failed "
                    "for '%s': %s",
                    item,
                    exc,
                )

                try:

                    self.ftp.cwd(
                        "/"
                    )

                    if path:
                        self.ftp.cwd(
                            path
                        )

                except Exception:
                    pass

        return collected

    # ========================================================================
    # Sensitive file classification
    # ========================================================================

    def classify_discovered_files(
        self,
        files,
    ):
        """
        Categorize discovered filenames.

        Classification is heuristic.

        A filename match does NOT prove that a file contains sensitive
        information.
        """

        categories = {

            "credentials": [
                ".env",
                "passwd",
                "shadow",
                "id_rsa",
                "config.json",
                "credentials.txt",
            ],

            "configs": [
                ".conf",
                ".ini",
                ".cfg",
                "config",
                "settings.xml",
            ],

            "databases": [
                ".sql",
                ".db",
                ".sqlite",
                ".mdb",
            ],

            "backups": [
                ".bak",
                ".zip",
                ".tar",
                ".gz",
                ".tgz",
            ],

            "code": [
                ".php",
                ".py",
                ".js",
                ".asp",
                ".aspx",
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

            for (
                category,
                keywords,
            ) in categories.items():

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

        # --------------------------------------------------------------------
        # Credential-bearing files
        # --------------------------------------------------------------------

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
                    "Accessible credential-related files may "
                    "expose secrets, credentials, configuration "
                    "variables, or private keys."
                ),
            )

        # --------------------------------------------------------------------
        # Databases
        # --------------------------------------------------------------------

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
                    "Accessible database files may expose "
                    "application data or backend structure."
                ),
            )

        # --------------------------------------------------------------------
        # Backups
        # --------------------------------------------------------------------

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

        # --------------------------------------------------------------------
        # Configuration files
        # --------------------------------------------------------------------

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
    # Write permission test
    # ========================================================================

    def test_upload_permissions(
        self,
    ):
        """
        Verify whether the current FTP session can create a temporary file.

        The test uses a uniquely named file and attempts cleanup.
        """

        if (
            self.result["status"]
            != "OPEN"
            or not self.ftp
        ):
            return

        test_filename = (
            f"pivotraid_audit_"
            f"{int(time.time())}.txt"
        )

        try:

            self.ftp.storbinary(
                f"STOR {test_filename}",
                io.BytesIO(
                    b"PivotRaid controlled permission test"
                ),
            )

            self.result[
                "writable"
            ] = True

            self.add_finding(
                title=(
                    "FTP session permits file creation"
                ),
                severity="HIGH",
                confidence="HIGH",
                category="authorization",
                evidence={
                    "test_file": test_filename,
                    "operation": "STOR",
                },
                impact=(
                    "The authenticated FTP context can create "
                    "files in the tested directory."
                ),
            )

            # ------------------------------------------------------------
            # Cleanup
            # ------------------------------------------------------------

            try:

                self.ftp.delete(
                    test_filename
                )

                self.add_finding(
                    title=(
                        "FTP permission-test file "
                        "successfully removed"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="cleanup",
                    evidence={
                        "test_file": test_filename,
                        "cleanup": "successful",
                    },
                )

            except Exception as exc:

                self.add_finding(
                    title=(
                        "FTP permission-test file "
                        "could not be removed"
                    ),
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="cleanup",
                    evidence={
                        "test_file": test_filename,
                        "cleanup": "failed",
                        "error": str(exc),
                    },
                    impact=(
                        "The controlled write test succeeded, "
                        "but automatic cleanup failed."
                    ),
                )

                logger.warning(
                    "Could not remove FTP test file "
                    "%s: %s",
                    test_filename,
                    exc,
                )

        except (
            error_perm,
            error_temp,
            OSError,
        ) as exc:

            logger.debug(
                "FTP write permission denied: %s",
                exc,
            )

            self.add_finding(
                title=(
                    "FTP write permission denied"
                ),
                severity="INFO",
                confidence="HIGH",
                category="authorization",
                evidence={
                    "operation": "STOR",
                    "result": "denied",
                },
            )

        except Exception as exc:

            logger.debug(
                "FTP write permission test failed: %s",
                exc,
            )

    # ========================================================================
    # Transport security
    # ========================================================================

    def record_transport_risk(
        self,
    ):
        """
        Record that standard FTP does not inherently protect
        credentials/session data with encryption.

        This is an observation, not a local risk calculation.
        """

        self.add_finding(
            title=(
                "Standard FTP does not provide "
                "encrypted transport"
            ),
            severity="MEDIUM",
            confidence="HIGH",
            category="transport_security",
            evidence={
                "protocol": "FTP",
                "encrypted_transport": False,
            },
            impact=(
                "Credentials and session data may be exposed "
                "to network observers unless an encrypted FTP "
                "variant or protected transport is used."
            ),
        )

    # ========================================================================
    # Main execution
    # ========================================================================

    def execute_scan(
        self,
    ):
        """
        Execute the FTP assessment in a controlled sequence.
        """

        start_time = time.time()

        logger.info(
            "Beginning FTP security assessment "
            "on %s:%s",
            self.target,
            self.port,
        )

        try:

            # --------------------------------------------------------------
            # Layer 1: Connection / fingerprinting
            # --------------------------------------------------------------

            if not self.finger_print_service():

                return self._finalize(
                    start_time
                )

            # --------------------------------------------------------------
            # Layer 2: Authentication
            # --------------------------------------------------------------

            self.audit_authentication()

            if not self.result[
                "anonymous"
            ]:

                self.audit_weak_credentials()

            # --------------------------------------------------------------
            # Layer 3: File enumeration
            # --------------------------------------------------------------

            files = self.list_files_safely(
                depth=2
            )

            if files:

                self.result[
                    "evidence"
                ][
                    "sample_files"
                ] = files[:15]

                self.add_finding(
                    title=(
                        f"FTP file enumeration "
                        f"discovered {len(files)} entries"
                    ),
                    severity="INFO",
                    confidence="HIGH",
                    category="enumeration",
                    evidence={
                        "file_count": len(files),
                        "sample_files": files[:15],
                    },
                )

                self.classify_discovered_files(
                    files
                )

            # --------------------------------------------------------------
            # Layer 4: Authorization
            # --------------------------------------------------------------

            self.test_upload_permissions()

            # --------------------------------------------------------------
            # Layer 5: Transport
            # --------------------------------------------------------------

            self.record_transport_risk()

        except Exception as exc:

            logger.critical(
                "FTP scanner runtime failure: %s",
                exc,
                exc_info=True,
            )

            self.add_finding(
                title=(
                    "FTP scan terminated unexpectedly"
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

    # ========================================================================
    # Connection cleanup
    # ========================================================================

    def close(
        self,
    ):
        """
        Safely close the FTP session.
        """

        if not self.ftp:
            return

        try:

            self.ftp.quit()

        except Exception:

            try:

                self.ftp.close()

            except Exception:
                pass

        finally:

            self.ftp = None

    # ========================================================================
    # Result finalization
    # ========================================================================

    def _finalize(
        self,
        start_time,
    ):
        """
        Finalize timing and compatibility fields.

        Global risk scoring and attack-path generation remain outside
        this scanner.
        """

        self.result[
            "scan_time"
        ] = round(
            time.time()
            - start_time,
            2,
        )

        # --------------------------------------------------------------------
        # Scanner-local compatibility fields.
        #
        # These are intentionally NOT risk calculations.
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
            "FTP scan completed on %s in %.2fs",
            self.target,
            self.result[
                "scan_time"
            ],
        )

        return self.result


# ============================================================================
# Standardized Interface
# ============================================================================

def scan_ftp(
    target,
    timeout=5,
):
    """
    Standard PivotRaid FTP scanner interface.
    """

    scanner = FTPScanner(
        target=target,
        timeout=timeout,
    )

    return scanner.execute_scan()
