"""Security assessment synthesis using OpenAI."""
import logging
import json
from openai import AsyncOpenAI
from typing import Dict, Any, List
from ..config import settings
from ..models import Assessment

logger = logging.getLogger(__name__)


class SecuritySynthesizer:
    """Synthesize security assessments using AI."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def synthesize_assessment(
        self,
        product_name: str,
        vendor_name: str,
        official_website: str,
        category: str,
        description: str,
        cve_data: Dict[str, Any],
        kev_data: Dict[str, Any],
        security_pages: Dict[str, Any],
        terms_privacy: Dict[str, Any],
    ) -> Assessment:
        """
        Synthesize comprehensive security assessment.

        Args:
            product_name: Product name
            vendor_name: Vendor name
            official_website: Official website URL
            category: Product category
            description: Product description
            cve_data: CVE vulnerability data from NVD
            kev_data: CISA KEV data
            security_pages: Scraped security page data
            terms_privacy: Terms and privacy URLs

        Returns:
            Complete Assessment object
        """
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(
            product_name,
            vendor_name,
            official_website,
            category,
            description,
            cve_data,
            kev_data,
            security_pages,
            terms_privacy,
        )

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            data = json.loads(content)

            logger.info(f"Synthesized assessment for {product_name}, score: {data.get('trust_score', {}).get('score')}")

            return Assessment(**data)

        except Exception as e:
            logger.error(f"Assessment synthesis failed: {str(e)}")
            raise

    def _build_system_prompt(self) -> str:
        """Build the comprehensive system prompt for assessment."""
        return """You are a senior security analyst creating CISO-ready trust briefs for software products.

Your role is to synthesize security posture assessments that help security decision-makers evaluate risk.

CRITICAL REQUIREMENTS:

1. EVIDENCE & CITATIONS (HIGHEST PRIORITY - 24% of score):
   - EVERY claim must have a citation using [1][2] format
   - Tag EVERY source as "vendor-stated" or "independent"
   - Citations must be real URLs from the provided data
   - When data is missing, explicitly state "Insufficient public evidence" - DO NOT GUESS or HALLUCINATE
   - Prefer independent sources over vendor claims when available

2. TRUST SCORE TRANSPARENCY (8% of score):
   - Base score starts at 50
   - Clearly explain calculation breakdown
   - Show specific adjustments with rationale
   - Confidence level must reflect data availability

3. CVE ANALYSIS:
   - Calculate trend by comparing recent vs older CVEs
   - Assess patch cadence based on publication dates
   - Highlight critical vulnerabilities in CISA KEV
   - Consider context (old software = more CVEs but might be well-maintained)

4. SECURITY POSTURE:
   - Focus on: vendor reputation, data handling, compliance, deployment controls
   - Distinguish vendor-stated vs independently verified
   - Note absence of information where relevant

5. ALTERNATIVES (6% of score):
   - Suggest based on ACTUAL security differences
   - Be specific: "Better patch record (30 day avg vs 90 day)"
   - Not generic: "More secure" without evidence

6. INCIDENTS:
   - Only report known breaches/incidents with sources
   - If none found, state "No known breaches found in public sources"

DATA QUALITY:
- HIGH: Multiple independent sources, compliance certs, CVE data available
- MEDIUM: Some vendor sources, limited CVE data
- LOW: Minimal public information

CONFIDENCE:
- HIGH: Rich data from multiple source types (independent + vendor + CVE)
- MEDIUM: Partial data, mostly vendor-stated or limited CVEs
- LOW: Scarce public evidence

Return ONLY valid JSON matching the exact schema provided."""

    def _build_user_prompt(
        self,
        product_name: str,
        vendor_name: str,
        official_website: str,
        category: str,
        description: str,
        cve_data: Dict[str, Any],
        kev_data: Dict[str, Any],
        security_pages: Dict[str, Any],
        terms_privacy: Dict[str, Any],
    ) -> str:
        """Build user prompt with all collected data."""
        return f"""Assess the security posture of this product:

PRODUCT INFORMATION:
- Product: {product_name}
- Vendor: {vendor_name}
- Website: {official_website}
- Category: {category}
- Description: {description}

CVE DATA:
{json.dumps(cve_data, indent=2)}

CISA KEV DATA:
{json.dumps(kev_data, indent=2)}

SECURITY PAGES FOUND:
{json.dumps(security_pages, indent=2)}

TERMS & PRIVACY:
{json.dumps(terms_privacy, indent=2)}

Generate a complete security assessment in JSON format with this EXACT schema:

{{
  "product_name": "{product_name}",
  "vendor_name": "{vendor_name}",
  "official_website": "{official_website}",
  "category": "{category}",
  "description": "{description}",

  "security_posture": {{
    "summary": "2-3 sentence overview WITH citations [1][2]",
    "vendor_reputation": "Company background, incidents WITH citations",
    "data_handling": "What data collected, where stored, encryption WITH citations",
    "compliance": ["SOC2", "ISO27001"],
    "deployment_controls": "SSO, audit logs, admin features WITH citations"
  }},

  "cve_analysis": {{
    "total_cves": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "trend": "increasing/stable/decreasing",
    "in_cisa_kev": false,
    "notable_cves": [
      {{
        "id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "description": "Brief description",
        "patched": true,
        "source": "url"
      }}
    ],
    "patch_cadence": "fast/medium/slow/unknown",
    "citations": ["url1"]
  }},

  "incidents": {{
    "known_breaches": "Description WITH citation or 'None found'",
    "abuse_signals": "Malware campaigns, phishing, etc WITH citation or 'None found'",
    "citations": []
  }},

  "trust_score": {{
    "score": 0-100,
    "confidence": "high/medium/low",
    "rationale": "Clear explanation",
    "risk_factors": ["Factor 1", "Factor 2", "Factor 3"],
    "trust_factors": ["Factor 1", "Factor 2", "Factor 3"],
    "calculation_breakdown": {{
      "base_score": 50,
      "cve_impact": -10,
      "certifications_bonus": 15,
      "breach_penalty": 0,
      "vendor_reputation": 5,
      "final": 60
    }}
  }},

  "alternatives": [
    {{
      "name": "Alternative Product",
      "vendor": "Vendor Name",
      "rationale": "Specific security advantage with evidence"
    }}
  ],

  "metadata": {{
    "assessed_at": "{json.dumps(None)}",
    "evidence_quality": "high/medium/low",
    "data_completeness": 0-100,
    "cache_hit": false
  }},

  "citations": {{
    "1": {{"url": "https://...", "type": "vendor-stated", "title": "Page title"}},
    "2": {{"url": "https://...", "type": "independent", "title": "Source name"}}
  }}
}}

REMEMBER:
- Every claim needs [citation]
- Tag every source as vendor-stated or independent
- Show trust score calculation clearly
- State "Insufficient public evidence" when data is missing
- Be specific and evidence-based"""

    def _build_assessment_json_schema(self) -> Dict[str, Any]:
        """Build JSON schema for response validation."""
        # This could be used for more strict validation if needed
        pass
