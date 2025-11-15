"""Pydantic models for CISO Insight."""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Citation(BaseModel):
    """Citation/source reference."""
    url: str
    type: str = Field(..., description="vendor-stated or independent")
    title: str


class NotableCVE(BaseModel):
    """Notable CVE entry."""
    id: str
    severity: str
    description: str
    patched: bool
    source: str


class CVEAnalysis(BaseModel):
    """CVE vulnerability analysis."""
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    trend: str = "unknown"
    in_cisa_kev: bool = False
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
    """Trust score calculation breakdown."""
    base_score: int = 50
    cve_impact: int = 0
    certifications_bonus: int = 0
    breach_penalty: int = 0
    vendor_reputation: int = 0
    final: int = 50


class TrustScore(BaseModel):
    """Trust score with transparency."""
    score: int = Field(..., ge=0, le=100)
    confidence: str = Field(..., description="high, medium, or low")
    rationale: str
    risk_factors: List[str] = []
    trust_factors: List[str] = []
    calculation_breakdown: TrustScoreCalculation


class Alternative(BaseModel):
    """Alternative product suggestion."""
    name: str
    vendor: str
    rationale: str


class AssessmentMetadata(BaseModel):
    """Assessment metadata."""
    assessed_at: str
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
