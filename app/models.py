"""Pydantic models for CISO Insight."""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator


class Citation(BaseModel):
    """Citation/source reference."""
    url: str
    type: str = Field(..., description="vendor-stated or independent")
    title: str


class NotableCVE(BaseModel):
    """Notable CVE entry."""
    id: str
    severity: str
    cvss_score: float = 0.0
    description: str
    patched: bool
    source: str
    version_range: str = None  # Affected version range (e.g., ">=2.0 AND <=2.5")


class KEVVulnerability(BaseModel):
    """CISA KEV vulnerability entry."""
    cve_id: str
    name: str
    vendor: str = ""
    product: str = ""
    date_added: str
    required_action: str = ""
    due_date: str = ""


class CVEAnalysis(BaseModel):
    """CVE vulnerability analysis."""
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    trend: str = "unknown"
    in_cisa_kev: bool = False
    kev_count: int = 0
    kev_vulnerabilities: List[KEVVulnerability] = []
    notable_cves: List[NotableCVE] = []
    patch_cadence: str = "unknown"
    citations: List[str] = []


class SecurityPosture(BaseModel):
    """Security posture summary."""
    summary: str
    vendor_reputation: str
    data_handling: str
    compliance: List[str] = []
    deployment_controls: str


class Incidents(BaseModel):
    """Security incidents."""
    known_breaches: str
    abuse_signals: str
    citations: List[str] = []


class TrustScoreCalculation(BaseModel):
    """Trust score calculation breakdown using explicit scoring model."""
    base_score: int = 100

    # Positive signals (bonuses) - Not used anymore, but kept for compatibility
    soc2_iso_bonus: int = 0
    security_page_bonus: int = 0
    bug_bounty_bonus: int = 0
    admin_controls_bonus: int = 0
    patch_cadence_bonus: int = 0

    # Negative signals (penalties)
    cisa_kev_penalty: int = 0
    critical_cve_penalty: int = 0
    high_cve_penalty: int = 0
    cert_advisory_penalty: int = 0
    breach_penalty: int = 0
    virustotal_penalty: int = 0
    no_security_page_penalty: int = 0
    no_compliance_penalty: int = 0
    no_terms_privacy_penalty: int = 0

    final: int = 0

    @model_validator(mode="after")
    def compute_final(cls, model: "TrustScoreCalculation") -> "TrustScoreCalculation":
        penalty_fields = [
            "cisa_kev_penalty",
            "critical_cve_penalty",
            "high_cve_penalty",
            "cert_advisory_penalty",
            "breach_penalty",
            "virustotal_penalty",
            "no_security_page_penalty",
            "no_compliance_penalty",
            "no_terms_privacy_penalty",
        ]
        total_penalties = sum(int(getattr(model, f) or 0) for f in penalty_fields)
        final = int(model.base_score or 0) - total_penalties
        model.final = max(0, min(final, 100))
        return model


class TrustScore(BaseModel):
    """Trust score with transparency."""
    score: None | int = Field(..., ge=0, le=100)
    confidence: str = Field(..., description="high, medium, or low")
    rationale: str
    risk_factors: List[str] = []
    trust_factors: List[str] = []
    calculation_breakdown: TrustScoreCalculation

    @model_validator(mode="after")
    def sync_score(cls, model: "TrustScore") -> "TrustScore":
        if getattr(model, "calculation_breakdown", None) is not None:
            model.score = int(model.calculation_breakdown.final or 0)
            model.score = max(0, min(model.score, 100))
        return model


class Alternative(BaseModel):
    """Alternative product suggestion."""
    name: str
    vendor: str
    rationale: str


class AssessmentMetadata(BaseModel):
    """Assessment metadata."""
    assessed_at: str | None
    evidence_quality: str = Field(..., description="high, medium, or low")
    data_completeness: int = Field(..., ge=0, le=100)
    cache_hit: bool = False


class Assessment(BaseModel):
    """Complete security assessment."""
    product_name: str
    vendor_name: str
    official_website: str
    category: str
    description: str
    version: str = "latest"
    sha1: Optional[str] = None
    security_posture: SecurityPosture
    cve_analysis: CVEAnalysis
    incidents: Incidents
    trust_score: TrustScore
    alternatives: List[Alternative] = []
    metadata: AssessmentMetadata
    citations: Dict[str, Citation]


class EntityResolution(BaseModel):
    """Resolved entity information."""
    product_name: str
    vendor_name: str
    official_website: str
    category: str
    description: str
    version: str = "latest"
    sha1: Optional[str] = None
