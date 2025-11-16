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
        version: str,
        sha1: str,
        cve_data: Dict[str, Any],
        kev_data: Dict[str, Any],
        security_pages: Dict[str, Any],
        terms_privacy: Dict[str, Any],
        virustotal_data: Dict[str, Any] = None,
    ) -> Assessment:
        """
        Synthesize comprehensive security assessment.

        Args:
            product_name: Product name
            vendor_name: Vendor name
            official_website: Official website URL
            category: Product category
            description: Product description
            version: Product version ('latest' or 'specific')
            sha1: SHA1 hash of specific version (if available)
            cve_data: CVE vulnerability data from NVD
            kev_data: CISA KEV data
            security_pages: Scraped security page data
            terms_privacy: Terms and privacy URLs
            virustotal_data: VirusTotal domain reputation data

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
            version,
            sha1,
            cve_data,
            kev_data,
            security_pages,
            terms_privacy,
            virustotal_data,
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

1. EVIDENCE & CITATIONS (HIGHEST PRIORITY - 24 percent of score):
   - EVERY claim must have a citation using [1][2] format
   - Tag EVERY source as "vendor-stated" or "independent"
   - Citations must be real URLs from the provided data
   - When data is missing, explicitly state "Insufficient public evidence" - DO NOT GUESS or HALLUCINATE
   - Prefer independent sources over vendor claims when available
   - IMPORTANT: Citations should ONLY include sources about the ASSESSED PRODUCT
   - DO NOT include URLs of alternative products in citations
   - Citations should include: CVE URLs, vendor security pages, VirusTotal reports, etc.

2. TRUST SCORE TRANSPARENCY (8 percent of score):
   - Base score starts at 100
   - Use this EXACT scoring model (SUBTRACT ONLY, NO BONUSES):

     VULNERABILITY SIGNALS (STRONGEST WEIGHT):
     -40 if ANY CISA KEV entry affects THIS VERSION
     -30 if there is at least ONE UNPATCHED CRITICAL CVE (CVSS 9.0–10.0) affecting THIS VERSION
     -15 if there is at least ONE PATCHED CRITICAL CVE affecting THIS VERSION
     -20 if there are 2+ UNPATCHED HIGH CVEs (CVSS 7.0–8.9) affecting THIS VERSION
     -10 if there is 1 UNPATCHED HIGH CVE affecting THIS VERSION
     -5 if there are ONLY PATCHED HIGH CVEs affecting THIS VERSION

     OTHER NEGATIVE SIGNALS (SECONDARY):
     -10 if there is a major CERT advisory for this product/version
     -10 if there is a publicly confirmed data breach in the last 12 months
     -10 if VirusTotal shows the vendor domain or binary hash flagged by 3+ security vendors
     -5 if VirusTotal shows the vendor domain or binary hash flagged by 1–2 security vendors
     -5 if no visible security or privacy/compliance page/docs found
     -5 if no SOC2 or ISO27001 or similar certification found
     -5 if no terms of service or privacy policy found

   - Final score = 100 - (sum of all penalties), clamped between 0 and 100
   - ALL CVE analysis MUST be version-specific, not generic
   - If applicability of CVEs to the given version is unclear, DO NOT count them as fully applicable; instead, mention them in the narrative with "uncertain applicability" and lower confidence.
   - Derive an overall TRUST LEVEL (low/medium/high) from the score AND vulnerability severity:

     • If ANY of the following are true:
        - in CISA KEV for this version
        - at least one UNPATCHED CRITICAL CVE for this version
       => TRUST LEVEL MUST be "low"
          and the numeric score MUST NOT exceed 40.

     • Else if ANY of the following are true:
        - at least one UNPATCHED HIGH CVE for this version
        - at least one PATCHED CRITICAL CVE for this version
        - a major CERT advisory exists for this product/version
        - a serious, confirmed data breach in the last 12 months
       => TRUST LEVEL MUST be "medium"
          and the numeric score MUST NOT exceed 75.

     • Else (no critical or high-severity issues affecting this version, no KEV, no major incidents)
       => TRUST LEVEL MAY be "high" if the score is >= 80.

   - IMPORTANT: TRUST LEVEL is about security risk. CONFIDENCE is about how certain we are about the assessment.

   - Confidence level ("high", "medium", or "low") is about how reliable the score is, NOT how safe the product is:

     • HIGH confidence:
       - Version is known and was used for all CVE filters
       - CVE data includes version-specific applicability (explicit version or clear ranges)
       - At least one of: NVD, OpenCVE, or CISA KEV was used
       - At least 8 citations total, including multiple independent sources
       - No major contradictions between sources

     • MEDIUM confidence:
       - Version is known, but some CVEs have unclear or generic applicability
       - CVE data exists, but only partially version-specific
       - 4-7 citations OR mostly vendor-stated sources with some independent evidence
       - Some gaps in security/compliance / VT / CERT data

     • LOW confidence:
       - Version is unknown, "latest", or mismatched across sources
       - CVE data is missing, generic, or cannot be tied clearly to this version
       - Fewer than 4 citations or almost all from vendor-stated sources
       - Insufficient public evidence to reliably assess risk

   - If CVE applicability to the given version is uncertain for most vulnerabilities, confidence MUST NOT be "high".

3. CVE ANALYSIS (VERSION-SPECIFIC REQUIRED):
   - CRITICAL: ALL CVE analysis MUST be specific to the provided version
   - VERIFY each CVE actually affects the version specified
   - Look for version numbers in CVE descriptions and affected version ranges
   - If a CVE description doesn't mention the specific version, check if it affects a range that includes it
   - If version is "latest", note this and analyze most recent CVEs
   - If CVE DATA comes from keyword search (not CPE-based), CAREFULLY verify version applicability
   - Calculate trend by comparing recent vs older CVEs for THIS version
   - Assess patch cadence based on publication dates
   - Highlight critical vulnerabilities in CISA KEV
   - For each notable CVE, verify if it affects the specific version by checking:
     * Is the version explicitly mentioned?
     * Does the affected version range include this version?
     * Is this a generic vulnerability affecting all versions?
   - If version-specific data unavailable or uncertain, state "Confidence: LOW" and explain why
   - Consider context (old software = more CVEs but might be well-maintained)
   - EXCLUDE CVEs that clearly don't affect the specified version

   CVSS SCORES (REQUIRED):
   - ALL notable CVEs MUST include CVSS score from CVE DATA
   - CVSS scores range from 0.0-10.0 using the Common Vulnerability Scoring System
   - CVSS Severity Ratings:
     • 9.0-10.0 = CRITICAL
     • 7.0-8.9 = HIGH
     • 4.0-6.9 = MEDIUM
     • 0.1-3.9 = LOW
   - Use CVSS scores to prioritize vulnerabilities in notable_cves
   - Include actual CVSS score for each notable CVE (e.g., 9.8, 7.5, 8.2)
   - For each notable CVE, analyze the description to determine if it's "patched": true/false
   - Set "source" to the NVD URL provided in CVE DATA

   CISA KEV VULNERABILITIES (CRITICAL):
   - Set in_cisa_kev to true if ANY KEV vulnerabilities found in CISA KEV DATA
   - Set kev_count to the number of KEV vulnerabilities found
   - Include ALL KEV vulnerabilities from the CISA KEV DATA in kev_vulnerabilities array
   - Each KEV entry must include: cve_id, name, vendor, product, date_added, required_action, due_date
   - KEV vulnerabilities are CRITICAL and actively exploited - emphasize urgency
   - IMPORTANT: If CISA KEV DATA shows vulnerabilities, ensure CVE analysis counts include them
   - KEV CVEs should also appear in notable_cves list (they are the most critical)
   - If KEV has CVEs but CVE DATA shows zero, this is an error - use KEV data to populate CVE counts

4. SECURITY POSTURE:
   - Focus on: vendor reputation, data handling, compliance, deployment controls
   - Distinguish vendor-stated vs independently verified
   - Note absence of information where relevant

5. ALTERNATIVES (6 percent of score):
   - Suggest EXACTLY 3 alternatives in the same category/industry
   - Alternatives don't need to be "safer" - they're for comparison purposes
   - Include well-known competitors or similar products
   - Provide brief rationale for why it's a relevant alternative (e.g., "Popular competitor", "Similar feature set", "Alternative approach to same problem")
   - ALWAYS provide 3 alternatives unless the product is extremely unique (then provide as many as possible)
   - Examples: If assessing Slack, suggest Teams, Discord, Mattermost
   - Examples: If assessing 1Password, suggest Bitwarden, LastPass, Dashlane

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
        version: str,
        sha1: str,
        cve_data: Dict[str, Any],
        kev_data: Dict[str, Any],
        security_pages: Dict[str, Any],
        terms_privacy: Dict[str, Any],
        virustotal_data: Dict[str, Any] = None,
    ) -> str:
        """Build user prompt with all collected data."""

        # Analyze data availability for transparency
        data_sources_summary = self._analyze_data_sources(
            cve_data, kev_data, security_pages, terms_privacy, virustotal_data
        )

        # Determine version source for context
        if sha1 and version != 'latest':
            version_info = f"{version} (verified via VirusTotal SHA1)"
            version_context = "Version is VERIFIED and SPECIFIC - use for accurate CVE analysis"
        elif version and version != 'latest':
            version_info = f"{version} (user-provided or auto-detected)"
            version_context = "Version is SPECIFIC - prioritize version-specific CVE analysis"
        else:
            version_info = "latest (unspecified)"
            version_context = "Version is UNKNOWN - analyze recent CVEs, note this affects confidence"

        return f"""Assess the security posture of this product:

PRODUCT INFORMATION:
- Product: {product_name}
- Vendor: {vendor_name}
- Website: {official_website}
- Category: {category}
- Description: {description}
- Version: {version_info}
- Version Context: {version_context}

DATA SOURCES AVAILABILITY:
{data_sources_summary}

CVE DATA:
{json.dumps(cve_data, indent=2)}

CISA KEV DATA:
{json.dumps(kev_data, indent=2)}

SECURITY PAGES FOUND:
{json.dumps(security_pages, indent=2)}

TERMS & PRIVACY:
{json.dumps(terms_privacy, indent=2)}

VIRUSTOTAL DOMAIN REPUTATION:
{json.dumps(virustotal_data or {}, indent=2)}

Generate a complete security assessment in JSON format with this EXACT schema:

{{
  "product_name": "{product_name}",
  "vendor_name": "{vendor_name}",
  "official_website": "{official_website}",
  "category": "{category}",
  "description": "{description}",
  "version": "{version}",
  "sha1": null,

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
    "kev_count": 0,
    "kev_vulnerabilities": [
      {{
        "cve_id": "CVE-2024-1234",
        "name": "Vulnerability name from CISA KEV catalog",
        "vendor": "Vendor name",
        "product": "Product name",
        "date_added": "2024-01-15",
        "required_action": "Apply updates per vendor instructions",
        "due_date": "2024-02-15"
      }}
    ],
    "notable_cves": [
      {{
        "id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
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
    "confidence": "high/medium/low",.
    "trust_level": "high/medium/low",
    "rationale": "Clear explanation of score with main factors listed",
    "risk_factors": ["Top 3 negative signals found", "Be specific", "Include evidence"],
    "trust_factors": ["Top 3 positive signals found", "Be specific", "Include evidence"],
    "calculation_breakdown": {{
      "base_score": 100,
      "soc2_iso_bonus": 0,
      "security_page_bonus": 0,
      "bug_bounty_bonus": 0,
      "admin_controls_bonus": 0,
      "patch_cadence_bonus": 0,
      "cisa_kev_penalty": 0,
      "critical_cve_penalty": 0,
      "high_cve_penalty": 0,
      "cert_advisory_penalty": 0,
      "breach_penalty": 0,
      "virustotal_penalty": 0,
      "no_security_page_penalty": 0,
      "no_compliance_penalty": 0,
      "no_terms_privacy_penalty": 0,
      "final": 100
    }}
  }},

  "alternatives": [
    {{
      "name": "Alternative Product 1",
      "vendor": "Vendor Name",
      "rationale": "Why this is a relevant alternative (e.g., Popular competitor, Similar feature set)"
    }},
    {{
      "name": "Alternative Product 2",
      "vendor": "Vendor Name",
      "rationale": "Why this is a relevant alternative"
    }},
    {{
      "name": "Alternative Product 3",
      "vendor": "Vendor Name",
      "rationale": "Why this is a relevant alternative"
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
- In calculation_breakdown:
    * base_score MUST be 100
    * All *_bonus fields MUST be 0 (we are not using bonuses in this version)
    * Only *_penalty fields should be non-zero, matching the rules above
    * final MUST equal 100 - sum(all penalties), clamped to [0, 100]
- Be specific and evidence-based"""

    def _analyze_data_sources(
        self,
        cve_data: Dict[str, Any],
        kev_data: Dict[str, Any],
        security_pages: Dict[str, Any],
        terms_privacy: Dict[str, Any],
        virustotal_data: Dict[str, Any] = None,
    ) -> str:
        """
        Analyze which data sources are available vs missing.

        This helps the AI provide better transparency about data gaps.
        """
        sources_found = []
        sources_missing = []

        # Check CVE data from NVD
        if cve_data.get("total_cves", 0) > 0:
            # Check if any notable CVEs have version_mentioned field (indicates CPE search was attempted)
            version_specific_search = False
            if cve_data.get("notable_cves"):
                for cve in cve_data["notable_cves"]:
                    if "version_mentioned" in cve:
                        version_specific_search = True
                        break

            search_method = " (CPE version-specific search)" if version_specific_search else " (keyword search - may include other versions)"
            sources_found.append(
                f"✓ CVE Data: {cve_data['total_cves']} vulnerabilities found from NVD{search_method} - independent source"
            )
        else:
            sources_found.append("✓ CVE Data: No CVEs found in NVD vulnerability database (GOOD)")

        # Check CISA KEV
        if kev_data.get("in_kev", False):
            kev_count = kev_data.get('kev_count', 0)
            sources_found.append(f"✓ CISA KEV: {kev_count} known exploited vulnerabilities (CRITICAL)")

            # Warn if KEV has CVEs but NVD search found nothing
            if kev_count > 0 and cve_data.get("total_cves", 0) == 0:
                sources_found.append(
                    f"⚠ WARNING: CISA KEV has {kev_count} CVEs but NVD search found 0. "
                    f"Ensure CVE analysis includes KEV vulnerabilities in counts and notable_cves."
                )
        else:
            sources_found.append("✓ CISA KEV: No known exploited vulnerabilities (GOOD)")

        # Check security pages
        if security_pages.get("security_pages_found"):
            pages_count = len(security_pages["security_pages_found"])
            sources_found.append(f"✓ Security Pages: {pages_count} pages found (vendor-stated)")
        else:
            sources_missing.append("✗ Security Pages: No dedicated security/PSIRT pages found")

        # Check bug bounty
        if security_pages.get("bug_bounty"):
            sources_found.append("✓ Bug Bounty Program: Found (vendor-stated)")
        else:
            sources_missing.append("✗ Bug Bounty Program: Not publicly disclosed")

        # Check certifications
        if security_pages.get("certifications"):
            certs = ", ".join(security_pages["certifications"])
            sources_found.append(f"✓ Certifications: {certs} (vendor-stated)")
        else:
            sources_missing.append("✗ Certifications: No SOC2/ISO27001 attestations found publicly")

        # Check Terms/Privacy
        if terms_privacy.get("terms_url") or terms_privacy.get("privacy_url"):
            sources_found.append("✓ Legal Documents: Terms of Service and/or Privacy Policy found")
        else:
            sources_missing.append("✗ Legal Documents: Terms/Privacy policy not found")

        # Check VirusTotal domain reputation
        if virustotal_data and virustotal_data.get("analyzed"):
            safety = virustotal_data.get("safety_score", "unknown")
            reputation = virustotal_data.get("reputation_score", 0)
            malicious = virustotal_data.get("detections", {}).get("malicious", 0)
            total = virustotal_data.get("detections", {}).get("total_engines", 0)

            if safety == "high_risk":
                sources_found.append(
                    f"⚠ VirusTotal Domain Reputation: HIGH RISK - {malicious}/{total} security vendors flagged this domain (independent, CRITICAL)"
                )
            elif safety == "medium_risk":
                sources_found.append(
                    f"⚠ VirusTotal Domain Reputation: MEDIUM RISK - {malicious}/{total} detections, reputation: {reputation} (independent)"
                )
            elif safety == "clean":
                sources_found.append(
                    f"✓ VirusTotal Domain Reputation: CLEAN - No malicious detections, reputation: {reputation} (independent)"
                )
            else:
                sources_found.append(
                    f"✓ VirusTotal Domain Reputation: Analyzed, {malicious}/{total} detections (independent)"
                )
        else:
            sources_missing.append("✗ VirusTotal Domain Reputation: Not analyzed or domain not found")

        summary = "DATA SOURCES FOUND:\n"
        summary += "\n".join(sources_found) if sources_found else "None"
        summary += "\n\nDATA SOURCES MISSING:\n"
        summary += "\n".join(sources_missing) if sources_missing else "None (all key sources found)"

        summary += "\n\nIMPORTANT: Use this summary to set confidence levels and data completeness scores. "
        summary += "When critical sources are missing, explicitly state 'Insufficient public evidence' in relevant sections."

        return summary

    def _build_assessment_json_schema(self) -> Dict[str, Any]:
        """Build JSON schema for response validation."""
        # This could be used for more strict validation if needed
        pass
