"""Security grading algorithm for container images."""

from datetime import datetime
from enum import Enum
from typing import Optional

from ..api.security_data import ContainerSecurityInfo, Severity
from ..utils.logging import get_logger

logger = get_logger("analysis.grading")


class SecurityGrade(str, Enum):
    """Security grade classifications."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    UNKNOWN = "Unknown"


class GradingCriteria:
    """Configuration for security grading criteria."""

    def __init__(self):
        # Base score deductions for vulnerability severities
        self.severity_weights = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
            Severity.UNKNOWN: 2,
        }

        # Additional penalties
        self.unpatched_critical_penalty = 10
        self.unpatched_high_penalty = 5
        self.age_penalty_per_month = 2
        self.max_age_penalty = 15

        # Grade thresholds (score ranges)
        self.grade_thresholds = {
            SecurityGrade.A: (90, 100),
            SecurityGrade.B: (80, 89),
            SecurityGrade.C: (70, 79),
            SecurityGrade.D: (60, 69),
            SecurityGrade.F: (0, 59),
        }

    def update_weights(self, **kwargs) -> None:
        """Update grading weights.

        Args:
            **kwargs: Weight parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)


class SecurityGrader:
    """Security grading engine for container images."""

    def __init__(self, criteria: Optional[GradingCriteria] = None):
        """Initialize the security grader.

        Args:
            criteria: Optional custom grading criteria
        """
        self.criteria = criteria or GradingCriteria()

    def grade_container(
        self, security_info: ContainerSecurityInfo, redhat_grade: Optional[str] = None
    ) -> tuple[SecurityGrade, int, dict[str, any]]:
        """Grade a container's security posture.

        Args:
            security_info: Container security information
            redhat_grade: Optional Red Hat provided grade

        Returns:
            Tuple of (grade, score, breakdown_details)
        """
        logger.debug(f"Grading container: {security_info.container_name}")

        # Use Red Hat grade if available and valid
        if redhat_grade and self._is_valid_grade(redhat_grade):
            logger.info(f"Using Red Hat provided grade: {redhat_grade}")
            return (
                SecurityGrade(redhat_grade),
                self._grade_to_score(redhat_grade),
                {"source": "red_hat", "grade": redhat_grade},
            )

        # Calculate score using our algorithm
        score, breakdown = self._calculate_security_score(security_info)
        grade = self._score_to_grade(score)

        logger.info(
            f"Container {security_info.container_name} graded: {grade.value} "
            f"(score: {score})"
        )

        return grade, score, breakdown

    def grade_multiple_containers(
        self,
        containers_info: list[ContainerSecurityInfo],
        redhat_grades: Optional[dict[str, str]] = None,
    ) -> list[tuple[str, SecurityGrade, int, dict[str, any]]]:
        """Grade multiple containers.

        Args:
            containers_info: List of container security information
            redhat_grades: Optional mapping of container names to Red Hat grades

        Returns:
            List of tuples: (container_name, grade, score, breakdown)
        """
        results = []
        redhat_grades = redhat_grades or {}

        for security_info in containers_info:
            rh_grade = redhat_grades.get(security_info.container_name)
            grade, score, breakdown = self.grade_container(security_info, rh_grade)

            results.append((security_info.container_name, grade, score, breakdown))

        return results

    def _calculate_security_score(
        self, security_info: ContainerSecurityInfo
    ) -> tuple[int, dict[str, any]]:
        """Calculate security score using vulnerability data.

        Args:
            security_info: Container security information

        Returns:
            Tuple of (score, breakdown_details)
        """
        base_score = 100
        breakdown = {
            "base_score": base_score,
            "vulnerability_penalties": {},
            "age_penalties": {},
            "unpatched_penalties": {},
            "total_penalties": 0,
            "final_score": base_score,
        }

        # Get vulnerability summary
        vuln_summary = security_info.vulnerability_summary

        # Calculate vulnerability penalties
        vuln_penalty = 0
        for severity, count in vuln_summary.items():
            if count > 0:
                try:
                    severity_enum = Severity(severity)
                    penalty = count * self.criteria.severity_weights[severity_enum]
                    vuln_penalty += penalty
                    breakdown["vulnerability_penalties"][severity] = {
                        "count": count,
                        "penalty_per_vuln": self.criteria.severity_weights[
                            severity_enum
                        ],
                        "total_penalty": penalty,
                    }
                except (ValueError, KeyError):
                    logger.warning(f"Unknown severity level: {severity}")
                    continue

        # Calculate age penalties
        age_penalty = self._calculate_age_penalty(security_info.vulnerabilities)
        breakdown["age_penalties"] = age_penalty

        # Calculate unpatched vulnerability penalties
        unpatched_penalty = self._calculate_unpatched_penalty(
            security_info.vulnerabilities
        )
        breakdown["unpatched_penalties"] = unpatched_penalty

        # Calculate total penalties
        total_penalty = vuln_penalty + age_penalty["total"] + unpatched_penalty["total"]
        breakdown["total_penalties"] = total_penalty

        # Calculate final score
        final_score = max(0, base_score - total_penalty)
        breakdown["final_score"] = final_score

        logger.debug(
            f"Score calculation for {security_info.container_name}: "
            f"base={base_score}, penalties={total_penalty}, final={final_score}"
        )

        return final_score, breakdown

    def _calculate_age_penalty(self, vulnerabilities: list) -> dict[str, any]:
        """Calculate penalty for old vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability data

        Returns:
            Dictionary with age penalty breakdown
        """
        age_breakdown = {
            "vulnerabilities_analyzed": 0,
            "aged_vulnerabilities": 0,
            "total": 0,
            "details": [],
        }

        current_date = datetime.now()

        for vuln in vulnerabilities:
            age_breakdown["vulnerabilities_analyzed"] += 1

            # Calculate age in months
            age_months = (current_date - vuln.published_date).days / 30.44

            if age_months > 1:  # Only penalize vulnerabilities older than 1 month
                penalty = min(
                    int(age_months) * self.criteria.age_penalty_per_month,
                    self.criteria.max_age_penalty,
                )

                if penalty > 0:
                    age_breakdown["aged_vulnerabilities"] += 1
                    age_breakdown["total"] += penalty
                    age_breakdown["details"].append(
                        {
                            "cve_id": vuln.cve_id,
                            "age_months": round(age_months, 1),
                            "penalty": penalty,
                        }
                    )

        return age_breakdown

    def _calculate_unpatched_penalty(self, vulnerabilities: list) -> dict[str, any]:
        """Calculate penalty for unpatched vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability data

        Returns:
            Dictionary with unpatched penalty breakdown
        """
        unpatched_breakdown = {
            "total_vulnerabilities": len(vulnerabilities),
            "unpatched_critical": 0,
            "unpatched_high": 0,
            "total": 0,
            "details": [],
        }

        for vuln in vulnerabilities:
            # Consider vulnerability unpatched if no fix version is available
            if not vuln.fixed_in_version:
                penalty = 0

                if vuln.severity == Severity.CRITICAL:
                    penalty = self.criteria.unpatched_critical_penalty
                    unpatched_breakdown["unpatched_critical"] += 1
                elif vuln.severity == Severity.HIGH:
                    penalty = self.criteria.unpatched_high_penalty
                    unpatched_breakdown["unpatched_high"] += 1

                if penalty > 0:
                    unpatched_breakdown["total"] += penalty
                    unpatched_breakdown["details"].append(
                        {
                            "cve_id": vuln.cve_id,
                            "severity": vuln.severity.value,
                            "penalty": penalty,
                        }
                    )

        return unpatched_breakdown

    def _score_to_grade(self, score: int) -> SecurityGrade:
        """Convert numeric score to letter grade.

        Args:
            score: Numeric security score

        Returns:
            Security grade
        """
        for grade, (min_score, max_score) in self.criteria.grade_thresholds.items():
            if min_score <= score <= max_score:
                return grade

        return SecurityGrade.F

    def _grade_to_score(self, grade: str) -> int:
        """Convert letter grade to approximate numeric score.

        Args:
            grade: Letter grade

        Returns:
            Approximate numeric score
        """
        try:
            grade_enum = SecurityGrade(grade)
            min_score, max_score = self.criteria.grade_thresholds[grade_enum]
            # Return middle of the range
            return (min_score + max_score) // 2
        except (ValueError, KeyError):
            return 0

    def _is_valid_grade(self, grade: str) -> bool:
        """Check if a grade string is valid.

        Args:
            grade: Grade string to validate

        Returns:
            True if valid grade
        """
        try:
            SecurityGrade(grade)
            return True
        except ValueError:
            return False

    def get_grade_distribution(
        self, graded_containers: list[tuple[str, SecurityGrade, int, dict]]
    ) -> dict[str, int]:
        """Get distribution of grades across containers.

        Args:
            graded_containers: List of graded container tuples

        Returns:
            Dictionary with grade counts
        """
        distribution = {grade.value: 0 for grade in SecurityGrade}

        for _, grade, _, _ in graded_containers:
            distribution[grade.value] += 1

        return distribution

    def get_security_summary(
        self, graded_containers: list[tuple[str, SecurityGrade, int, dict]]
    ) -> dict[str, any]:
        """Get overall security summary for a set of containers.

        Args:
            graded_containers: List of graded container tuples

        Returns:
            Security summary statistics
        """
        if not graded_containers:
            return {
                "total_containers": 0,
                "average_score": 0,
                "grade_distribution": {},
                "security_posture": "unknown",
            }

        scores = [score for _, _, score, _ in graded_containers]
        average_score = sum(scores) / len(scores)

        grade_distribution = self.get_grade_distribution(graded_containers)

        # Determine overall security posture
        posture = "good"
        if grade_distribution.get("F", 0) > 0:
            posture = "critical"
        elif grade_distribution.get("D", 0) > len(graded_containers) * 0.2:
            posture = "concerning"
        elif average_score < 80:
            posture = "needs_improvement"

        return {
            "total_containers": len(graded_containers),
            "average_score": round(average_score, 1),
            "grade_distribution": grade_distribution,
            "security_posture": posture,
            "best_grade": max(grade.value for _, grade, _, _ in graded_containers),
            "worst_grade": min(grade.value for _, grade, _, _ in graded_containers),
        }


def create_grader(custom_criteria: Optional[dict] = None) -> SecurityGrader:
    """Create a security grader with optional custom criteria.

    Args:
        custom_criteria: Optional dictionary of custom grading criteria

    Returns:
        Configured SecurityGrader instance
    """
    criteria = GradingCriteria()

    if custom_criteria:
        criteria.update_weights(**custom_criteria)

    return SecurityGrader(criteria)
