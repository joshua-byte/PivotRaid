import logging


logger = logging.getLogger("PivotRaid.Risk")


class RiskEngine:
    """
    Calculate target-level risk from structured scanner results.

    SearchSploit results are treated as vulnerability candidates unless
    independently confirmed. This engine does not claim exploitability
    from the existence of an exploit record alone.
    """

    # ------------------------------------------------------------------
    # Scoring configuration
    # ------------------------------------------------------------------

    SEVERITY_WEIGHT = {
        "INFO": 0,
        "LOW": 8,
        "MEDIUM": 18,
        "HIGH": 32,
        "CRITICAL": 50,
    }

    CONFIDENCE_MULTIPLIER = {
        "LOW": 0.50,
        "MEDIUM": 0.75,
        "HIGH": 1.00,
    }

    SERVICE_MULTIPLIER = {
        "FTP": 1.00,
        "SMB": 1.05,
        "SSH": 0.95,
    }

    CATEGORY_FACTORS = (
        1.00,
        0.55,
        0.30,
        0.15,
    )

    CANDIDATE_MULTIPLIER = 0.35
    CANDIDATE_SERVICE_CAP = 20
    CANDIDATE_TARGET_CAP = 35

    CONFIRMED_MULTIPLIER = 1.00

    CROSS_SERVICE_CAP = 30

    OBSERVED_SCORE_SOFT_CAP = 75
    CANDIDATE_SCORE_SOFT_CAP = 25
    CONFIRMED_SCORE_SOFT_CAP = 40
    CROSS_SERVICE_SCORE_SOFT_CAP = 25

    CRITICAL_THRESHOLD = 85
    HIGH_THRESHOLD = 65
    MEDIUM_THRESHOLD = 40
    LOW_THRESHOLD = 15

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_assessment(service_count=0):
        """Return a fresh assessment structure."""

        return {
            "score": 0,
            "severity": "INFO",
            "confidence": "LOW",
            "verdict": "",
            "finding_count": 0,
            "service_count": service_count,
            "severity_counts": {
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            },
            "confirmed_vulnerabilities": 0,
            "vulnerability_candidates": 0,
            "risk_factors": [],
            "services": {},
            "score_breakdown": {
                "observed_exposure": 0,
                "vulnerability_candidates": 0,
                "confirmed_vulnerabilities": 0,
                "cross_service": 0,
            },
        }

    def __init__(self):
        self.assessment = self._empty_assessment()

        self._finding_groups = {}
        self._candidate_service_scores = {}
        self._confirmed_score = 0
        self._cross_service_score = 0

    def _reset(self, service_count):
        """Reset internal state for a new assessment."""

        self.assessment = self._empty_assessment(service_count)

        self._finding_groups = {}
        self._candidate_service_scores = {}
        self._confirmed_score = 0
        self._cross_service_score = 0

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_severity(value):
        severity = str(value or "INFO").upper()

        if severity not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return "INFO"

        return severity

    @staticmethod
    def _normalize_confidence(value):
        confidence = str(value or "LOW").upper()

        if confidence not in {
            "LOW",
            "MEDIUM",
            "HIGH",
        }:
            return "LOW"

        return confidence

    @staticmethod
    def _normalize_service(value):
        return str(value or "UNKNOWN").upper()

    # ------------------------------------------------------------------
    # Finding scoring
    # ------------------------------------------------------------------

    def calculate_finding_score(
        self,
        finding,
        service="",
        multiplier=1.0,
    ):
        """
        Calculate an internal PivotRaid risk contribution.

        This is not CVSS, probability of exploitation, or vulnerability
        confirmation.
        """

        if not isinstance(finding, dict):
            return 0

        severity = self._normalize_severity(
            finding.get("severity")
        )

        confidence = self._normalize_confidence(
            finding.get("confidence")
        )

        if severity == "INFO":
            return 0

        base = self.SEVERITY_WEIGHT[severity]

        confidence_multiplier = (
            self.CONFIDENCE_MULTIPLIER[confidence]
        )

        service_multiplier = self.SERVICE_MULTIPLIER.get(
            self._normalize_service(service),
            1.0,
        )

        score = (
            base
            * confidence_multiplier
            * service_multiplier
            * multiplier
        )

        return round(score, 2)

    def _finding_group_key(self, service, finding):
        """Group findings by service and category."""

        service = self._normalize_service(service)

        category = str(
            finding.get("category", "general")
        ).lower().strip()

        return service, category

    def process_finding(self, finding, service=""):
        """Process one observed security finding."""

        if not isinstance(finding, dict):
            return

        service = self._normalize_service(service)

        severity = self._normalize_severity(
            finding.get("severity")
        )

        confidence = self._normalize_confidence(
            finding.get("confidence")
        )

        self.assessment["finding_count"] += 1
        self.assessment["severity_counts"][severity] += 1

        # Informational findings are reported but do not affect risk.
        if severity == "INFO":
            return

        group_key = self._finding_group_key(
            service,
            finding,
        )

        group_count = self._finding_groups.get(
            group_key,
            0,
        )

        factor_index = min(
            group_count,
            len(self.CATEGORY_FACTORS) - 1,
        )

        diminishing_factor = self.CATEGORY_FACTORS[
            factor_index
        ]

        self._finding_groups[group_key] = group_count + 1

        contribution = self.calculate_finding_score(
            finding=finding,
            service=service,
            multiplier=diminishing_factor,
        )

        if contribution <= 0:
            return

        self.assessment["risk_factors"].append({
            "service": service,
            "title": finding.get(
                "title",
                "Unnamed finding",
            ),
            "severity": severity,
            "confidence": confidence,
            "contribution": contribution,
            "category": finding.get(
                "category",
                "general",
            ),
            "status": "OBSERVED",
            "aggregation": {
                "group": group_key[1],
                "position": group_count + 1,
                "diminishing_factor": diminishing_factor,
            },
        })

        self.assessment["score_breakdown"][
            "observed_exposure"
        ] += contribution

    # ------------------------------------------------------------------
    # Vulnerability processing
    # ------------------------------------------------------------------

    def process_vulnerability(
        self,
        vulnerability,
        service="",
    ):
        """
        Process a vulnerability candidate or confirmed vulnerability.

        Candidates receive reduced and capped risk contribution.
        Confirmed vulnerabilities receive their full contribution.
        """

        if not isinstance(vulnerability, dict):
            return

        service = self._normalize_service(service)

        confirmed = bool(
            vulnerability.get(
                "confirmed",
                False,
            )
        )

        if confirmed:
            self.assessment[
                "confirmed_vulnerabilities"
            ] += 1
        else:
            self.assessment[
                "vulnerability_candidates"
            ] += 1

        severity = self._normalize_severity(
            vulnerability.get("severity")
        )

        confidence = self._normalize_confidence(
            vulnerability.get("confidence")
        )

        finding = {
            "severity": severity,
            "confidence": confidence,
        }

        if confirmed:
            contribution = self.calculate_finding_score(
                finding=finding,
                service=service,
                multiplier=self.CONFIRMED_MULTIPLIER,
            )

            if contribution <= 0:
                return

            self._confirmed_score += contribution

            self.assessment["risk_factors"].append({
                "service": service,
                "title": vulnerability.get(
                    "title",
                    "Confirmed vulnerability",
                ),
                "severity": severity,
                "confidence": confidence,
                "contribution": contribution,
                "category": "vulnerability",
                "status": "CONFIRMED",
                "edb_id": vulnerability.get("id"),
            })

            return

        # Unconfirmed vulnerability candidate.
        contribution = self.calculate_finding_score(
            finding=finding,
            service=service,
            multiplier=self.CANDIDATE_MULTIPLIER,
        )

        if contribution <= 0:
            return

        self._candidate_service_scores[service] = (
            self._candidate_service_scores.get(
                service,
                0,
            )
            + contribution
        )

        self.assessment["risk_factors"].append({
            "service": service,
            "title": vulnerability.get(
                "title",
                "Potential vulnerability",
            ),
            "severity": severity,
            "confidence": confidence,
            "contribution": round(
                contribution,
                2,
            ),
            "category": "vulnerability",
            "status": "CANDIDATE",
            "edb_id": vulnerability.get("id"),
        })

    def _aggregate_candidate_scores(self):
        """
        Cap vulnerability candidate contribution.

        Individual candidates remain visible in the report, while the
        aggregate capped score affects the target score.
        """

        if not self._candidate_service_scores:
            self.assessment["score_breakdown"][
                "vulnerability_candidates"
            ] = 0

            return 0

        service_total = 0

        for total in self._candidate_service_scores.values():
            service_total += min(
                total,
                self.CANDIDATE_SERVICE_CAP,
            )

        capped_total = min(
            service_total,
            self.CANDIDATE_TARGET_CAP,
        )

        self.assessment["score_breakdown"][
            "vulnerability_candidates"
        ] = round(
            capped_total,
            2,
        )

        return capped_total

    # ------------------------------------------------------------------
    # Service processing
    # ------------------------------------------------------------------

    def process_service(self, service_result):
        """Process one normalized service result."""

        if not isinstance(service_result, dict):
            return

        service = self._normalize_service(
            service_result.get(
                "service",
                "UNKNOWN",
            )
        )

        findings = service_result.get(
            "findings",
            [],
        )

        vulnerabilities = service_result.get(
            "vulns",
            [],
        )

        if not isinstance(findings, list):
            findings = []

        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        self.assessment["services"][service] = {
            "status": service_result.get(
                "status",
                "UNKNOWN",
            ),
            "finding_count": len(findings),
            "vulnerability_count": len(vulnerabilities),
        }

        for finding in findings:
            self.process_finding(
                finding,
                service,
            )

        for vulnerability in vulnerabilities:
            self.process_vulnerability(
                vulnerability,
                service,
            )

    # ------------------------------------------------------------------
    # Cross-service rules
    # ------------------------------------------------------------------

    def apply_cross_service_rules(self, service_results):
        """
        Apply limited cross-service risk relationships.

        Cross-service contribution is capped separately from individual
        service exposure.
        """

        services = {}

        for result in service_results or []:
            if not isinstance(result, dict):
                continue

            name = self._normalize_service(
                result.get("service", "")
            )

            if name:
                services[name] = result

        ftp = services.get("FTP")
        smb = services.get("SMB")

        # FTP + SMB exposure.
        if ftp and smb:
            ftp_exposure = (
                bool(ftp.get("anonymous", False))
                or bool(ftp.get("writable", False))
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

            smb_exposure = (
                bool(
                    smb.get(
                        "accessible_shares",
                        [],
                    )
                )
                or bool(smb.get("anonymous", False))
            )

            if ftp_exposure and smb_exposure:
                self._add_cross_service_factor({
                    "service": "CROSS-SERVICE",
                    "title": (
                        "FTP and SMB both expose "
                        "server-side file resources"
                    ),
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "contribution": 10,
                    "category": "cross_service_exposure",
                    "status": "OBSERVED",
                })

        # Credential exposure + SSH.
        ssh = services.get("SSH")

        if ssh and str(
            ssh.get("status", "")
        ).upper() == "OPEN":
            credential_exposure = False

            for service_name in ("FTP", "SMB"):
                result = services.get(service_name)

                if not result:
                    continue

                classified = result.get(
                    "classified_hits",
                    {},
                )

                if classified.get("credentials"):
                    credential_exposure = True
                    break

            if credential_exposure:
                self._add_cross_service_factor({
                    "service": "CROSS-SERVICE",
                    "title": (
                        "Potential credential exposure "
                        "coexists with externally accessible SSH"
                    ),
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "contribution": 12,
                    "category": "credential_pivot",
                    "status": "POTENTIAL",
                })

    def _add_cross_service_factor(self, factor):
        """Add a cross-service factor while respecting the cap."""

        contribution = float(
            factor.get(
                "contribution",
                0,
            )
        )

        remaining = max(
            self.CROSS_SERVICE_CAP
            - self._cross_service_score,
            0,
        )

        applied = min(
            contribution,
            remaining,
        )

        if applied <= 0:
            return

        factor["contribution"] = round(
            applied,
            2,
        )

        self.assessment["risk_factors"].append(
            factor
        )

        self._cross_service_score += applied

        self.assessment["score_breakdown"][
            "cross_service"
        ] = round(
            self._cross_service_score,
            2,
        )

    # ------------------------------------------------------------------
    # Score normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _soft_cap(value, cap):
        """
        Apply a smooth cap.

        Values beyond the cap still contribute, but at a reduced rate.
        """

        value = max(float(value), 0)
        cap = max(float(cap), 1)

        if value <= cap:
            return value

        return cap + (value - cap) * 0.35

    def calculate_target_score(self):
        """Calculate the final target-level score from 0 to 100."""

        observed = float(
            self.assessment["score_breakdown"][
                "observed_exposure"
            ]
        )

        candidates = float(
            self.assessment["score_breakdown"][
                "vulnerability_candidates"
            ]
        )

        confirmed = float(
            self._confirmed_score
        )

        cross_service = float(
            self.assessment["score_breakdown"][
                "cross_service"
            ]
        )

        observed_component = self._soft_cap(
            observed,
            self.OBSERVED_SCORE_SOFT_CAP,
        )

        candidate_component = self._soft_cap(
            candidates,
            self.CANDIDATE_SCORE_SOFT_CAP,
        )

        confirmed_component = self._soft_cap(
            confirmed,
            self.CONFIRMED_SCORE_SOFT_CAP,
        )

        cross_service_component = self._soft_cap(
            cross_service,
            self.CROSS_SERVICE_SCORE_SOFT_CAP,
        )

        total = (
            observed_component
            + candidate_component
            + confirmed_component
            + cross_service_component
        )

        score = min(
            max(round(total), 0),
            100,
        )

        self.assessment["score"] = score

        self.assessment["score_breakdown"][
            "confirmed_vulnerabilities"
        ] = round(
            confirmed_component,
            2,
        )

        return score

    # ------------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------------

    def determine_severity(self):
        """Convert the target score into a severity class."""

        score = self.assessment["score"]

        if score >= self.CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif score >= self.HIGH_THRESHOLD:
            severity = "HIGH"
        elif score >= self.MEDIUM_THRESHOLD:
            severity = "MEDIUM"
        elif score >= self.LOW_THRESHOLD:
            severity = "LOW"
        else:
            severity = "INFO"

        self.assessment["severity"] = severity

        return severity

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    def determine_confidence(self):
        """
        Determine confidence in the overall assessment.

        Multiple findings alone do not automatically produce high
        confidence. Observed and confirmed evidence are stronger than
        inferred vulnerability candidates.
        """

        factors = self.assessment["risk_factors"]

        if not factors:
            confidence = "LOW"

        else:
            observed = [
                factor
                for factor in factors
                if factor.get("status") == "OBSERVED"
            ]

            confirmed = [
                factor
                for factor in factors
                if factor.get("status") == "CONFIRMED"
            ]

            candidates = [
                factor
                for factor in factors
                if factor.get("status") == "CANDIDATE"
            ]

            high_observed = sum(
                1
                for factor in observed
                if factor.get("confidence") == "HIGH"
            )

            medium_observed = sum(
                1
                for factor in observed
                if factor.get("confidence") == "MEDIUM"
            )

            strong_evidence = (
                high_observed
                + len(confirmed)
            )

            if (
                strong_evidence >= 2
                and len(observed) > 0
            ):
                confidence = "HIGH"

            elif (
                strong_evidence >= 1
                or medium_observed >= 2
            ):
                confidence = "MEDIUM"

            elif candidates:
                confidence = "MEDIUM"

            else:
                confidence = "LOW"

        self.assessment["confidence"] = confidence

        return confidence

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------

    def generate_verdict(self):
        """Generate the final human-readable assessment."""

        severity = self.assessment["severity"]
        confidence = self.assessment["confidence"]
        score = self.assessment["score"]

        confirmed = self.assessment[
            "confirmed_vulnerabilities"
        ]

        candidates = self.assessment[
            "vulnerability_candidates"
        ]

        statements = {
            "CRITICAL": (
                "CRITICAL – Multiple significant "
                "security exposures are present."
            ),
            "HIGH": (
                "HIGH – Significant security "
                "exposure has been identified."
            ),
            "MEDIUM": (
                "MEDIUM – Material security "
                "weaknesses have been identified."
            ),
            "LOW": (
                "LOW – Limited security exposure "
                "has been identified."
            ),
            "INFO": (
                "INFO – No significant exposure was identified "
                "within the observed scan results; this is not "
                "a guarantee that the target is secure."
            ),
        }

        statement = statements.get(
            severity,
            statements["INFO"],
        )

        if candidates and not confirmed:
            qualification = (
                f" {candidates} vulnerability candidate(s) "
                "were identified, but none are confirmed "
                "as exploitable."
            )

        elif candidates and confirmed:
            qualification = (
                f" {confirmed} vulnerability finding(s) "
                f"are confirmed and {candidates} additional "
                "candidate(s) remain unconfirmed."
            )

        elif confirmed:
            qualification = (
                f" {confirmed} vulnerability finding(s) "
                "are confirmed."
            )

        else:
            qualification = ""

        self.assessment["verdict"] = (
            f"{statement}"
            f"{qualification} "
            f"Assessment confidence: {confidence}. "
            f"Risk score: {score}/100."
        )

        return self.assessment["verdict"]

    # ------------------------------------------------------------------
    # Risk factor sorting
    # ------------------------------------------------------------------

    def sort_risk_factors(self):
        """Sort risk factors consistently for reporting."""

        severity_rank = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        status_rank = {
            "CONFIRMED": 3,
            "OBSERVED": 2,
            "POTENTIAL": 1,
            "CANDIDATE": 0,
        }

        self.assessment["risk_factors"].sort(
            key=lambda factor: (
                severity_rank.get(
                    factor.get(
                        "severity",
                        "INFO",
                    ),
                    0,
                ),
                status_rank.get(
                    factor.get(
                        "status",
                        "CANDIDATE",
                    ),
                    0,
                ),
                factor.get(
                    "contribution",
                    0,
                ),
            ),
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Complete assessment
    # ------------------------------------------------------------------

    def assess(self, service_results):
        """Execute the complete target-level risk assessment."""

        if not service_results:
            self._reset(0)
            return self.assessment

        self._reset(len(service_results))

        for service_result in service_results:
            self.process_service(service_result)

        self._aggregate_candidate_scores()

        self.apply_cross_service_rules(
            service_results
        )

        self.calculate_target_score()
        self.determine_severity()
        self.determine_confidence()
        self.generate_verdict()
        self.sort_risk_factors()

        logger.info(
            "Risk assessment complete: %s (%s/100, confidence=%s)",
            self.assessment["severity"],
            self.assessment["score"],
            self.assessment["confidence"],
        )

        return self.assessment


# ============================================================================
# Convenience Interface
# ============================================================================

def assess_risk(service_results):
    """Convenience wrapper used by main.py."""

    engine = RiskEngine()

    return engine.assess(service_results)
