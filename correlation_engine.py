import logging


logger = logging.getLogger("PivotRaid.Correlation")


# ============================================================================
# Correlation Engine
# ============================================================================

class CorrelationEngine:
    """
    PivotRaid cross-service correlation engine.

    Purpose:
        Transform independent service findings into relationships
        and potential exposure paths.

    Inputs:
        FTP, SMB, SSH, and vulnerability assessment results.

    Outputs:
        - relationships
        - potential attack paths
        - path confidence
        - path severity
        - supporting evidence

    This engine does NOT:
        - execute exploits
        - generate payloads
        - generate attack commands
        - authenticate to services
        - prove exploitability
    """

    SEVERITY_RANK = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    CONFIDENCE_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    def __init__(self):

        self.services = {}

        self.relationships = []

        self.attack_paths = []

    # ========================================================================
    # Utility
    # ========================================================================

    @staticmethod
    def normalize_service(service):

        return str(
            service or "UNKNOWN"
        ).upper()

    @classmethod
    def severity_max(
        cls,
        *severities,
    ):
        """
        Return the highest severity from supplied values.
        """

        valid = [
            str(
                severity or "INFO"
            ).upper()
            for severity in severities
        ]

        if not valid:
            return "INFO"

        return max(
            valid,
            key=lambda value: cls.SEVERITY_RANK.get(
                value,
                0,
            ),
        )

    @classmethod
    def confidence_min(
        cls,
        *confidences,
    ):
        """
        Return the weakest confidence among supplied values.

        A relationship should never be more confident than its
        weakest supporting observation.
        """

        valid = [
            str(
                confidence or "LOW"
            ).upper()
            for confidence in confidences
        ]

        if not valid:
            return "LOW"

        return min(
            valid,
            key=lambda value: cls.CONFIDENCE_RANK.get(
                value,
                1,
            ),
        )

    # ========================================================================
    # Index services
    # ========================================================================

    def index_services(
        self,
        service_results,
    ):
        """
        Create a service lookup table.
        """

        self.services = {}

        for result in service_results or []:

            if not isinstance(
                result,
                dict,
            ):
                continue

            service = self.normalize_service(
                result.get(
                    "service"
                )
            )

            self.services[
                service
            ] = result

        logger.debug(
            "Indexed %d service result(s)",
            len(
                self.services
            ),
        )

    # ========================================================================
    # Finding helpers
    # ========================================================================

    @staticmethod
    def get_findings(
        service_result,
    ):
        """
        Return structured findings from a scanner result.
        """

        if not isinstance(
            service_result,
            dict,
        ):
            return []

        findings = service_result.get(
            "findings",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            return []

        return [
            finding
            for finding in findings
            if isinstance(
                finding,
                dict,
            )
        ]

    def find_findings(
        self,
        service,
        categories=None,
        severities=None,
    ):
        """
        Find structured findings belonging to a service.
        """

        result = self.services.get(
            self.normalize_service(
                service
            )
        )

        if not result:
            return []

        findings = self.get_findings(
            result
        )

        if categories:

            categories = {
                str(
                    category
                ).lower()
                for category in categories
            }

            findings = [
                finding
                for finding in findings
                if str(
                    finding.get(
                        "category",
                        "",
                    )
                ).lower()
                in categories
            ]

        if severities:

            severities = {
                str(
                    severity
                ).upper()
                for severity in severities
            }

            findings = [
                finding
                for finding in findings
                if str(
                    finding.get(
                        "severity",
                        "INFO",
                    )
                ).upper()
                in severities
            ]

        return findings

    # ========================================================================
    # Relationship creation
    # ========================================================================

    def add_relationship(
        self,
        source,
        destination,
        relationship,
        severity="MEDIUM",
        confidence="MEDIUM",
        evidence=None,
        rationale="",
    ):
        """
        Add a cross-service relationship.

        A relationship represents an inference supported by
        observations; it is not proof of exploitability.
        """

        relationship_data = {

            "source": source,

            "destination": destination,

            "relationship": relationship,

            "severity": str(
                severity
            ).upper(),

            "confidence": str(
                confidence
            ).upper(),

            "evidence": (
                evidence or []
            ),

            "rationale": rationale,
        }

        # --------------------------------------------------------------------
        # Avoid exact duplicate relationships.
        # --------------------------------------------------------------------

        for existing in self.relationships:

            if (
                existing.get(
                    "source"
                ) == relationship_data["source"]
                and existing.get(
                    "destination"
                ) == relationship_data["destination"]
                and existing.get(
                    "relationship"
                ) == relationship_data["relationship"]
            ):

                return existing

        self.relationships.append(
            relationship_data
        )

        logger.debug(
            "Correlation: %s -> %s (%s)",
            source,
            destination,
            relationship,
        )

        return relationship_data

    # ========================================================================
    # Attack path creation
    # ========================================================================

    def add_attack_path(
        self,
        name,
        steps,
        severity="MEDIUM",
        confidence="MEDIUM",
        rationale="",
        evidence=None,
    ):
        """
        Add a potential attack/exposure path.

        Steps describe security-relevant states rather than
        operational exploitation instructions.
        """

        path = {

            "name": name,

            "severity": str(
                severity
            ).upper(),

            "confidence": str(
                confidence
            ).upper(),

            "steps": steps,

            "rationale": rationale,

            "evidence": (
                evidence or []
            ),
        }

        self.attack_paths.append(
            path
        )

        return path

    # ========================================================================
    # Rule 1: Anonymous FTP
    # ========================================================================

    def correlate_anonymous_ftp(self):
        """
        Detect anonymous FTP exposure.
        """

        ftp = self.services.get(
            "FTP"
        )

        if not ftp:
            return

        if not ftp.get(
            "anonymous"
        ):
            return

        findings = self.find_findings(
            "FTP",
            categories={
                "authentication"
            },
        )

        supporting = [
            finding
            for finding in findings
            if "anonymous"
            in str(
                finding.get(
                    "title",
                    "",
                )
            ).lower()
        ]

        confidence = (
            supporting[0].get(
                "confidence",
                "HIGH",
            )
            if supporting
            else "HIGH"
        )

        self.add_attack_path(

            name="Anonymous FTP exposure",

            steps=[

                {
                    "stage": "access",

                    "service": "FTP",

                    "observation": (
                        "Anonymous FTP authentication "
                        "is permitted."
                    ),
                },

                {
                    "stage": "resource_access",

                    "service": "FTP",

                    "observation": (
                        "FTP resources may be accessible "
                        "without identified credentials."
                    ),
                },
            ],

            severity="HIGH",

            confidence=confidence,

            rationale=(
                "Anonymous authentication creates an "
                "unauthenticated access path to the FTP service."
            ),

            evidence=supporting,
        )

    # ========================================================================
    # Rule 2: Anonymous FTP + Sensitive Files
    # ========================================================================

    def correlate_ftp_sensitive_files(self):
        """
        Correlate anonymous FTP access with sensitive-looking files.
        """

        ftp = self.services.get(
            "FTP"
        )

        if not ftp:
            return

        if not ftp.get(
            "anonymous"
        ):
            return

        classified = ftp.get(
            "classified_hits",
            {},
        )

        credentials = classified.get(
            "credentials",
            [],
        )

        configs = classified.get(
            "configs",
            [],
        )

        sensitive_files = (
            credentials
            + configs
        )

        if not sensitive_files:
            return

        auth_findings = self.find_findings(
            "FTP",
            categories={
                "authentication"
            },
        )

        file_findings = self.find_findings(
            "FTP",
            categories={
                "file_exposure"
            },
        )

        auth_confidence = (
            auth_findings[0].get(
                "confidence",
                "MEDIUM",
            )
            if auth_findings
            else "MEDIUM"
        )

        file_confidence = (
            file_findings[0].get(
                "confidence",
                "MEDIUM",
            )
            if file_findings
            else "MEDIUM"
        )

        confidence = self.confidence_min(
            auth_confidence,
            file_confidence,
        )

        self.add_relationship(

            source="FTP anonymous access",

            destination="Potential sensitive files",

            relationship="may_expose",

            severity="CRITICAL",

            confidence=confidence,

            evidence=(
                auth_findings
                + file_findings
            ),

            rationale=(
                "Anonymous FTP access and filename-based "
                "sensitive-file indicators occur together."
            ),
        )

        self.add_attack_path(

            name=(
                "Anonymous FTP to sensitive-file exposure"
            ),

            steps=[

                {
                    "stage": "access",

                    "service": "FTP",

                    "observation": (
                        "Anonymous authentication is permitted."
                    ),
                },

                {
                    "stage": "enumeration",

                    "service": "FTP",

                    "observation": (
                        "Potentially sensitive files were "
                        "identified by filename heuristics."
                    ),

                    "evidence": sensitive_files[:25],
                },

                {
                    "stage": "potential_impact",

                    "service": "FTP",

                    "observation": (
                        "Exposed files may contain credentials, "
                        "configuration information, or secrets."
                    ),
                },
            ],

            severity="CRITICAL",

            confidence=confidence,

            rationale=(
                "The combination of anonymous access and "
                "potentially sensitive file exposure creates "
                "a meaningful information-disclosure path."
            ),

            evidence=(
                auth_findings
                + file_findings
            ),
        )

    # ========================================================================
    # Rule 3: Writable FTP
    # ========================================================================

    def correlate_writable_ftp(self):
        """
        Identify writable FTP exposure.
        """

        ftp = self.services.get(
            "FTP"
        )

        if not ftp:
            return

        if not ftp.get(
            "writable"
        ):
            return

        findings = self.find_findings(
            "FTP",
            categories={
                "authorization"
            },
        )

        supporting = [
            finding
            for finding in findings
            if "file creation"
            in str(
                finding.get(
                    "title",
                    "",
                )
            ).lower()
        ]

        confidence = (
            supporting[0].get(
                "confidence",
                "HIGH",
            )
            if supporting
            else "HIGH"
        )

        self.add_attack_path(

            name="Writable FTP resource exposure",

            steps=[

                {
                    "stage": "access",

                    "service": "FTP",

                    "observation": (
                        "The current FTP session can "
                        "create files."
                    ),
                },

                {
                    "stage": "potential_impact",

                    "service": "FTP",

                    "observation": (
                        "Writable server-side resources may "
                        "create additional security exposure."
                    ),
                },
            ],

            severity="HIGH",

            confidence=confidence,

            rationale=(
                "Write permission expands the capabilities "
                "available through the FTP service."
            ),

            evidence=supporting,
        )

    # ========================================================================
    # Rule 4: SMB readable shares
    # ========================================================================

    def correlate_smb_shares(self):
        """
        Identify accessible SMB shares.
        """

        smb = self.services.get(
            "SMB"
        )

        if not smb:
            return

        accessible = smb.get(
            "accessible_shares",
            [],
        )

        if not accessible:
            return

        findings = self.find_findings(
            "SMB",
            categories={
                "authorization"
            },
        )

        supporting = [
            finding
            for finding in findings
            if "share is readable"
            in str(
                finding.get(
                    "title",
                    "",
                )
            ).lower()
        ]

        confidence = "HIGH"

        if supporting:

            confidence = self.confidence_min(
                *[
                    finding.get(
                        "confidence",
                        "MEDIUM",
                    )
                    for finding in supporting
                ]
            )

        self.add_attack_path(

            name="Accessible SMB share exposure",

            steps=[

                {
                    "stage": "access",

                    "service": "SMB",

                    "observation": (
                        "One or more SMB shares are "
                        "accessible to the current session."
                    ),

                    "evidence": accessible,
                },

                {
                    "stage": "resource_access",

                    "service": "SMB",

                    "observation": (
                        "Share contents can be enumerated "
                        "within the available permissions."
                    ),
                },
            ],

            severity="HIGH",

            confidence=confidence,

            rationale=(
                "Accessible SMB shares expose server-side "
                "resources to the current authentication context."
            ),

            evidence=supporting,
        )

    # ========================================================================
    # Rule 5: SMB + Sensitive Files
    # ========================================================================

    def correlate_smb_sensitive_files(self):
        """
        Correlate accessible SMB shares with sensitive-looking files.
        """

        smb = self.services.get(
            "SMB"
        )

        if not smb:
            return

        accessible = smb.get(
            "accessible_shares",
            [],
        )

        classified = smb.get(
            "classified_hits",
            {},
        )

        credentials = classified.get(
            "credentials",
            [],
        )

        databases = classified.get(
            "databases",
            [],
        )

        backups = classified.get(
            "backups",
            [],
        )

        configs = classified.get(
            "configs",
            [],
        )

        sensitive_files = (
            credentials
            + databases
            + backups
            + configs
        )

        if (
            not accessible
            or not sensitive_files
        ):
            return

        findings = self.find_findings(
            "SMB",
            categories={
                "file_exposure"
            },
        )

        confidence = (
            findings[0].get(
                "confidence",
                "MEDIUM",
            )
            if findings
            else "MEDIUM"
        )

        severity = (
            "CRITICAL"
            if credentials
            else "HIGH"
        )

        self.add_relationship(

            source="SMB accessible share",

            destination="Potential sensitive files",

            relationship="may_expose",

            severity=severity,

            confidence=confidence,

            evidence=findings,

            rationale=(
                "Accessible SMB shares coincide with "
                "filename indicators for potentially sensitive files."
            ),
        )

        self.add_attack_path(

            name="SMB share to sensitive-file exposure",

            steps=[

                {
                    "stage": "access",

                    "service": "SMB",

                    "observation": (
                        "An SMB share is accessible."
                    ),

                    "evidence": accessible,
                },

                {
                    "stage": "enumeration",

                    "service": "SMB",

                    "observation": (
                        "Potentially sensitive files were "
                        "identified using filename heuristics."
                    ),

                    "evidence": sensitive_files[:25],
                },

                {
                    "stage": "potential_impact",

                    "service": "SMB",

                    "observation": (
                        "The files may expose credentials, "
                        "configuration, databases, or backups."
                    ),
                },
            ],

            severity=severity,

            confidence=confidence,

            rationale=(
                "Readable SMB resources combined with "
                "sensitive-file indicators create a potential "
                "information-disclosure path."
            ),

            evidence=findings,
        )

    # ========================================================================
    # Rule 6: SMB signing
    # ========================================================================

    def correlate_smb_signing(self):
        """
        Record SMB signing posture as a security relationship.

        The engine does not claim that relay is possible; it only
        records the relevant exposure condition.
        """

        smb = self.services.get(
            "SMB"
        )

        if not smb:
            return

        signing_required = (
            smb.get(
                "evidence",
                {},
            ).get(
                "signing_required"
            )
        )

        if signing_required is not False:
            return

        findings = self.find_findings(
            "SMB",
            categories={
                "protocol_security"
            },
        )

        self.add_relationship(

            source="SMB",

            destination="Authentication integrity",

            relationship="reduced_protection",

            severity="HIGH",

            confidence="HIGH",

            evidence=findings,

            rationale=(
                "SMB signing is not required. This is a security "
                "posture weakness, although exploitability depends "
                "on the surrounding network configuration."
            ),
        )

    # ========================================================================
    # Rule 7: Credential exposure + SSH
    # ========================================================================

    def correlate_credentials_to_ssh(self):
        """
        Correlate credential-bearing file indicators with
        an externally accessible SSH service.

        This is intentionally expressed as a potential relationship,
        not as proof that the credentials work against SSH.
        """

        ssh = self.services.get(
            "SSH"
        )

        if not ssh:
            return

        if ssh.get(
            "status"
        ) != "OPEN":
            return

        credential_services = []

        for service in [
            "FTP",
            "SMB",
        ]:

            result = self.services.get(
                service
            )

            if not result:
                continue

            classified = result.get(
                "classified_hits",
                {},
            )

            credentials = classified.get(
                "credentials",
                [],
            )

            if credentials:

                credential_services.append({

                    "service": service,

                    "files": credentials,
                })

        if not credential_services:
            return

        credential_findings = []

        for item in credential_services:

            credential_findings.extend(
                self.find_findings(
                    item["service"],
                    categories={
                        "file_exposure"
                    },
                )
            )

        ssh_findings = self.find_findings(
            "SSH",
            categories={
                "fingerprinting"
            },
        )

        confidence = self.confidence_min(
            *[
                finding.get(
                    "confidence",
                    "MEDIUM",
                )
                for finding in (
                    credential_findings
                    + ssh_findings
                )
            ]
        )

        self.add_relationship(

            source="Credential-bearing file exposure",

            destination="Externally accessible SSH",

            relationship=(
                "potential_authentication_dependency"
            ),

            severity="HIGH",

            confidence=confidence,

            evidence=(
                credential_findings
                + ssh_findings
            ),

            rationale=(
                "Credential-bearing files were identified on one "
                "service while SSH is externally accessible. "
                "The relationship is potential only; credential "
                "reuse has not been established."
            ),
        )

        steps = []

        for item in credential_services:

            steps.append({

                "stage": "initial_access",

                "service": item["service"],

                "observation": (
                    "Potential credential-bearing files "
                    "were identified."
                ),

                "evidence": item[
                    "files"
                ][:25],
            })

        steps.extend([

            {
                "stage": "destination",

                "service": "SSH",

                "observation": (
                    "SSH is externally accessible."
                ),
            },

            {
                "stage": "qualification",

                "service": "SSH",

                "observation": (
                    "Credential reuse or validity has "
                    "not been established."
                ),
            },
        ])

        self.add_attack_path(

            name=(
                "Credential exposure to potential SSH access"
            ),

            steps=steps,

            severity="HIGH",

            confidence=confidence,

            rationale=(
                "Credential exposure and SSH accessibility "
                "create a potential cross-service relationship, "
                "but the credentials must not be assumed valid."
            ),

            evidence=(
                credential_findings
                + ssh_findings
            ),
        )

    # ========================================================================
    # Rule 8: FTP + SMB
    # ========================================================================

    def correlate_ftp_smb(self):
        """
        Identify combined file-service exposure.
        """

        ftp = self.services.get(
            "FTP"
        )

        smb = self.services.get(
            "SMB"
        )

        if not ftp or not smb:
            return

        ftp_exposed = (

            bool(
                ftp.get(
                    "anonymous"
                )
            )

            or bool(
                ftp.get(
                    "writable"
                )
            )

            or bool(
                ftp.get(
                    "classified_hits",
                    {},
                ).get(
                    "credentials",
                    [],
                )
            )
        )

        smb_exposed = bool(
            smb.get(
                "accessible_shares",
                [],
            )
        )

        if not (
            ftp_exposed
            and smb_exposed
        ):
            return

        supporting = (
            self.get_findings(
                ftp
            )
            + self.get_findings(
                smb
            )
        )

        confidence = "MEDIUM"

        if supporting:

            confidence = self.confidence_min(
                *[
                    finding.get(
                        "confidence",
                        "MEDIUM",
                    )
                    for finding in supporting
                ]
            )

        self.add_relationship(

            source="FTP",

            destination="SMB",

            relationship=(
                "combined_file_service_exposure"
            ),

            severity="HIGH",

            confidence=confidence,

            evidence=supporting,

            rationale=(
                "Both FTP and SMB expose server-side file "
                "resources, increasing the overall information "
                "exposure surface."
            ),
        )

    # ========================================================================
    # Rule 9: Vulnerability candidates
    # ========================================================================

    def correlate_vulnerability_candidates(self):
        """
        Associate vulnerability candidates with the service on which
        they were identified.

        IMPORTANT:

        SearchSploit candidates are aggregated PER SERVICE.

        We intentionally do not create one relationship per exploit
        record because that produces relationship inflation.

        Individual exploit records remain available under:

            service_result["vulns"]

        The relationship communicates the existence of vulnerability
        intelligence, not individual exploitability.
        """

        for service, result in self.services.items():

            vulnerabilities = result.get(
                "vulns",
                [],
            )

            if not isinstance(
                vulnerabilities,
                list,
            ):
                continue

            if not vulnerabilities:
                continue

            valid_vulnerabilities = [
                vulnerability
                for vulnerability in vulnerabilities
                if isinstance(
                    vulnerability,
                    dict,
                )
            ]

            if not valid_vulnerabilities:
                continue

            # ---------------------------------------------------------------
            # Separate confirmed and unconfirmed candidates.
            # ---------------------------------------------------------------

            confirmed = [
                vulnerability
                for vulnerability in valid_vulnerabilities
                if vulnerability.get(
                    "confirmed",
                    False,
                )
            ]

            candidates = [
                vulnerability
                for vulnerability in valid_vulnerabilities
                if not vulnerability.get(
                    "confirmed",
                    False,
                )
            ]

            # ---------------------------------------------------------------
            # Nothing to correlate.
            # ---------------------------------------------------------------

            if not (
                candidates
                or confirmed
            ):
                continue

            # ---------------------------------------------------------------
            # Determine relationship severity from the strongest candidate.
            # ---------------------------------------------------------------

            severity_values = [

                str(
                    vulnerability.get(
                        "severity",
                        "INFO",
                    )
                ).upper()

                for vulnerability in valid_vulnerabilities
            ]

            severity = self.severity_max(
                *severity_values
            )

            # ---------------------------------------------------------------
            # Determine relationship confidence.
            #
            # SearchSploit candidates generally don't carry an explicit
            # confidence value. We therefore default to MEDIUM rather
            # than pretending the candidate itself is high-confidence.
            # ---------------------------------------------------------------

            confidence_values = [

                str(
                    vulnerability.get(
                        "confidence",
                        "MEDIUM",
                    )
                ).upper()

                for vulnerability in valid_vulnerabilities
            ]

            confidence = self.confidence_min(
                *confidence_values
            )

            # ---------------------------------------------------------------
            # Candidate relationship
            # ---------------------------------------------------------------

            if candidates:

                candidate_titles = [

                    vulnerability.get(
                        "title",
                        "Unknown vulnerability candidate",
                    )

                    for vulnerability in candidates
                ]

                self.add_relationship(

                    source=service,

                    destination="Vulnerability assessment",

                    relationship=(
                        "potential_vulnerability"
                    ),

                    severity=severity,

                    confidence=confidence,

                    evidence=candidates,

                    rationale=(
                        f"SearchSploit identified "
                        f"{len(candidates)} potentially relevant "
                        f"exploit record(s) for {service}. "
                        "These records are vulnerability candidates "
                        "and do not establish target exploitability."
                    ),
                )

                logger.debug(
                    "%s vulnerability correlation: "
                    "%d candidate(s)",
                    service,
                    len(candidates),
                )

            # ---------------------------------------------------------------
            # Confirmed relationship
            # ---------------------------------------------------------------

            if confirmed:

                self.add_relationship(

                    source=service,

                    destination="Vulnerability assessment",

                    relationship=(
                        "confirmed_vulnerability"
                    ),

                    severity=self.severity_max(
                        *[
                            str(
                                vulnerability.get(
                                    "severity",
                                    "INFO",
                                )
                            ).upper()
                            for vulnerability in confirmed
                        ]
                    ),

                    confidence=self.confidence_min(
                        *[
                            str(
                                vulnerability.get(
                                    "confidence",
                                    "HIGH",
                                )
                            ).upper()
                            for vulnerability in confirmed
                        ]
                    ),

                    evidence=confirmed,

                    rationale=(
                        f"{len(confirmed)} vulnerability "
                        f"finding(s) are marked as confirmed "
                        f"for {service}."
                    ),
                )

    # ========================================================================
    # Deduplicate paths
    # ========================================================================

    def deduplicate_paths(self):
        """
        Remove duplicate paths by semantic name.
        """

        unique = []

        seen = set()

        for path in self.attack_paths:

            key = str(
                path.get(
                    "name",
                    "",
                )
            ).strip().lower()

            if not key:
                continue

            if key in seen:
                continue

            seen.add(
                key
            )

            unique.append(
                path
            )

        self.attack_paths = unique

    # ========================================================================
    # Sort relationships
    # ========================================================================

    def sort_relationships(self):
        """
        Sort relationships by severity and confidence.
        """

        self.relationships.sort(

            key=lambda relationship: (

                self.SEVERITY_RANK.get(
                    relationship.get(
                        "severity",
                        "INFO",
                    ),
                    0,
                ),

                self.CONFIDENCE_RANK.get(
                    relationship.get(
                        "confidence",
                        "LOW",
                    ),
                    1,
                ),
            ),

            reverse=True,
        )

    # ========================================================================
    # Sort paths
    # ========================================================================

    def sort_paths(self):
        """
        Sort paths by severity and confidence.
        """

        self.attack_paths.sort(

            key=lambda path: (

                self.SEVERITY_RANK.get(
                    path.get(
                        "severity",
                        "INFO",
                    ),
                    0,
                ),

                self.CONFIDENCE_RANK.get(
                    path.get(
                        "confidence",
                        "LOW",
                    ),
                    1,
                ),
            ),

            reverse=True,
        )

    # ========================================================================
    # Main correlation
    # ========================================================================

    def correlate(
        self,
        service_results,
    ):
        """
        Run the complete cross-service correlation process.
        """

        self.services = {}

        self.relationships = []

        self.attack_paths = []

        self.index_services(
            service_results
        )

        # ====================================================================
        # Individual service relationships
        # ====================================================================

        self.correlate_anonymous_ftp()

        self.correlate_ftp_sensitive_files()

        self.correlate_writable_ftp()

        self.correlate_smb_shares()

        self.correlate_smb_sensitive_files()

        self.correlate_smb_signing()

        # ====================================================================
        # Cross-service relationships
        # ====================================================================

        self.correlate_credentials_to_ssh()

        self.correlate_ftp_smb()

        # ====================================================================
        # Vulnerability intelligence
        # ====================================================================

        self.correlate_vulnerability_candidates()

        # ====================================================================
        # Cleanup
        # ====================================================================

        self.deduplicate_paths()

        self.sort_relationships()

        self.sort_paths()

        logger.info(
            "Correlation complete: %d relationship(s), "
            "%d potential path(s)",
            len(
                self.relationships
            ),
            len(
                self.attack_paths
            ),
        )

        return {

            "relationships": (
                self.relationships
            ),

            "attack_paths": (
                self.attack_paths
            ),
        }


# ============================================================================
# Convenience Interface
# ============================================================================

def correlate_results(
    service_results,
):
    """
    Convenience wrapper for main.py.
    """

    engine = CorrelationEngine()

    return engine.correlate(
        service_results
    )
