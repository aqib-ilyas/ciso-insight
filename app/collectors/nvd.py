"""NVD CVE API client."""
import httpx
import logging
import asyncio
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from packaging import version as pkg_version
from openai import AsyncOpenAI
from ..config import settings

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for NIST NVD CVE API."""

    def __init__(self):
        self.base_url = settings.NVD_BASE_URL
        self.api_key = settings.NVD_API_KEY
        self.rate_limit_delay = settings.NVD_RATE_LIMIT
        self.openai_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

    async def _llm_check_version_affected(
        self,
        cve_id: str,
        description: str,
        target_version: str,
        product_name: str,
        version_ranges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Use LLM to determine if a CVE affects a specific version.

        Args:
            cve_id: CVE identifier
            description: CVE description
            target_version: Version to check (e.g., "26.0.0")
            product_name: Product name
            version_ranges: Extracted version ranges from CVE config

        Returns:
            Dict with 'affected' (bool), 'confidence' (float), 'reasoning' (str)
        """
        # Build version range summary
        version_info = ""
        if version_ranges:
            version_info = "Version ranges from NVD configuration:\n"
            for vr in version_ranges[:5]:  # Limit to first 5 ranges
                if vr.get("exact_version"):
                    version_info += f"- Exact version: {vr['exact_version']}\n"
                elif vr.get("version_start") or vr.get("version_end"):
                    start = vr.get("version_start", "any")
                    end = vr.get("version_end", "any")
                    start_type = vr.get("version_start_type", "including")
                    end_type = vr.get("version_end_type", "including")
                    version_info += f"- Range: {start} ({start_type}) to {end} ({end_type})\n"

        prompt = f"""You are analyzing CVE version applicability. Be PRECISE with version number comparisons.

PRODUCT: {product_name}
TARGET VERSION: {target_version}
CVE ID: {cve_id}

CVE DESCRIPTION:
{description[:500]}...

{version_info if version_info else "No structured version data from NVD."}

TASK: Does CVE {cve_id} affect {product_name} version {target_version}?

VERSION COMPARISON RULES:
1. Use semantic versioning: 15.71.4 > 14.7.1965
2. "up to X" or "before X" means versions < X are affected
3. "from X to Y" means X <= version <= Y (unless excluding)
4. "fixed in X" means versions >= X are NOT affected
5. "prior to X" means versions < X are affected

EXAMPLES:
- CVE affects "up to 14.7.1965" + Target: "15.71.4" → NOT AFFECTED (15.71.4 > 14.7.1965)
- CVE affects "versions 10.x through 14.x" + Target: "15.71.4" → NOT AFFECTED (15 > 14)
- CVE affects "all versions" → AFFECTED
- CVE affects "version 15.71.4" exactly + Target: "15.71.4" → AFFECTED

RESPONSE FORMAT (JSON only):
{{
  "affected": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Clear explanation with version comparison"
}}

IMPORTANT:
- If target version is HIGHER than affected range → affected: false
- If target version is LOWER than fixed version → affected: false
- If no version info available → affected: false, confidence: 0.2
- Be VERY careful with version number comparison!"""

        try:
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",  # Use mini for cost efficiency
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing CVE version applicability. Be precise and conservative."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )

            result = json.loads(response.choices[0].message.content)
            return {
                "affected": result.get("affected", False),
                "confidence": result.get("confidence", 0.5),
                "reasoning": result.get("reasoning", ""),
            }

        except Exception as e:
            logger.error(f"LLM version check failed for {cve_id}: {str(e)}")
            # Fallback: assume affected for safety
            return {
                "affected": True,
                "confidence": 0.5,
                "reasoning": f"LLM check failed, assuming affected for safety: {str(e)}"
            }

    def _normalize_version(self, version_str: str) -> Optional[pkg_version.Version]:
        """Normalize version string for comparison.

        Args:
            version_str: Version string (e.g., "2.5.0", "1.0", "latest")

        Returns:
            Parsed version object or None if invalid
        """
        if not version_str or version_str.lower() in ['latest', 'unknown', '*', '-']:
            return None

        try:
            # Clean version string - remove common prefixes/suffixes
            cleaned = version_str.strip().lstrip('v').lstrip('V')
            # Remove trailing wildcards
            cleaned = cleaned.rstrip('.*')

            return pkg_version.parse(cleaned)
        except Exception as e:
            logger.debug(f"Failed to parse version '{version_str}': {e}")
            return None

    def _is_version_affected(
        self,
        target_version: str,
        version_start: Optional[str] = None,
        version_start_type: str = "including",
        version_end: Optional[str] = None,
        version_end_type: str = "including"
    ) -> bool:
        """Check if target version falls within affected range.

        Args:
            target_version: Version to check
            version_start: Start of affected range
            version_start_type: "including" or "excluding"
            version_end: End of affected range
            version_end_type: "including" or "excluding"

        Returns:
            True if version is affected, False otherwise
        """
        target = self._normalize_version(target_version)
        if not target:
            return False

        # If no bounds specified at all, we can't determine - return False for safety
        if not version_start and not version_end:
            return False

        # Check lower bound
        if version_start:
            start = self._normalize_version(version_start)
            if start:
                if version_start_type == "including":
                    if target < start:
                        return False
                else:  # excluding
                    if target <= start:
                        return False

        # Check upper bound
        if version_end:
            end = self._normalize_version(version_end)
            if end:
                if version_end_type == "including":
                    if target > end:
                        return False
                else:  # excluding
                    if target >= end:
                        return False

        return True

    def _extract_affected_versions(self, cve_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract affected version ranges from CVE configurations.

        Args:
            cve_item: CVE item from NVD response

        Returns:
            List of version range dictionaries
        """
        version_ranges = []

        try:
            configurations = cve_item.get("cve", {}).get("configurations", [])

            for config in configurations:
                nodes = config.get("nodes", [])

                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])

                    for cpe_match in cpe_matches:
                        if not cpe_match.get("vulnerable"):
                            continue

                        version_range = {
                            "cpe": cpe_match.get("criteria", ""),
                            "version_start": cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding"),
                            "version_start_type": "including" if cpe_match.get("versionStartIncluding") else "excluding",
                            "version_end": cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding"),
                            "version_end_type": "including" if cpe_match.get("versionEndIncluding") else "excluding",
                        }

                        # Also extract version from CPE if exact match
                        has_version_info = False
                        cpe_parts = cpe_match.get("criteria", "").split(":")
                        if len(cpe_parts) >= 6:
                            cpe_version = cpe_parts[5]
                            if cpe_version and cpe_version not in ['*', '-']:
                                version_range["exact_version"] = cpe_version
                                has_version_info = True

                        # Check if we have any version bounds
                        if version_range.get("version_start") or version_range.get("version_end"):
                            has_version_info = True

                        # Only add if we have actual version information
                        if has_version_info:
                            version_ranges.append(version_range)

        except Exception as e:
            logger.debug(f"Failed to extract version ranges: {e}")

        return version_ranges

    async def search_cve_by_id(self, cve_id: str) -> Dict[str, Any]:
        """
        Search for a specific CVE by ID.

        Args:
            cve_id: CVE ID (e.g., CVE-2024-1234)

        Returns:
            Dict containing CVE data
        """
        try:
            params = {
                "cveId": cve_id,
            }

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                logger.info(f"Searching NVD for CVE ID: {cve_id}")
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

            return await self._process_cve_data(data, version_filter=None, product_name="")

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for {cve_id}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error for {cve_id}: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"NVD search failed for {cve_id}: {str(e)}")
            return self._empty_result()

    async def search_cves(self, product_name: str, vendor_name: str = None, version: str = None) -> Dict[str, Any]:
        """
        Search for CVEs related to a product and filter by version range.

        Args:
            product_name: Product name
            vendor_name: Vendor name (optional)
            version: Specific version to check against CVE ranges (optional)

        Returns:
            Dict containing CVE statistics and notable entries
        """
        try:
            # Use keyword search with product and vendor
            search_terms = [product_name]
            if vendor_name:
                search_terms.append(vendor_name)

            params = {
                "keywordSearch": " ".join(search_terms),
                "resultsPerPage": 100,
            }

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                logger.info(f"Searching NVD for: {' '.join(search_terms)}")
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

            # Process and filter by version ranges
            return await self._process_cve_data(data, version_filter=version, product_name=product_name)

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for {product_name}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"NVD search failed: {str(e)}")
            return self._empty_result()

    async def _process_cve_data(self, data: Dict[str, Any], version_filter: str = None, product_name: str = "") -> Dict[str, Any]:
        """
        Process NVD API response and filter by version using LLM.

        Args:
            data: NVD API response data
            version_filter: Optional version to filter against
            product_name: Product name for LLM context

        Returns:
            Processed CVE data with LLM-verified version filtering
        """
        vulnerabilities = data.get("vulnerabilities", [])
        total_raw_cves = len(vulnerabilities)

        if total_raw_cves == 0:
            return self._empty_result()

        # Count by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        notable_cves = []
        version_specific_count = 0
        version_filtered_cves = []

        logger.info(f"Processing {total_raw_cves} CVEs (version filter: {version_filter})")

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Get CVSS score and severity
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = 0.0

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    cvss_data = metrics[metric_type][0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    break

            # Get description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Version filtering - use LLM to check if CVE affects target version
            version_applicable = True  # Default to true if no version filter
            version_range_info = None
            llm_reasoning = None

            if version_filter and version_filter not in ['latest', 'unknown']:
                # Extract version ranges from CVE configuration
                version_ranges = self._extract_affected_versions(vuln)

                # Use LLM to determine if this CVE affects the target version
                llm_result = await self._llm_check_version_affected(
                    cve_id=cve_id,
                    description=description,
                    target_version=version_filter,
                    product_name=product_name,
                    version_ranges=version_ranges
                )

                version_applicable = llm_result["affected"]
                llm_reasoning = llm_result["reasoning"]

                # Build version range display from LLM reasoning or structured data
                if version_ranges and llm_result["affected"]:
                    # Try to extract a clean range summary
                    for vr in version_ranges:
                        if vr.get("exact_version"):
                            version_range_info = f"v{vr['exact_version']}"
                            break
                        elif vr.get("version_start") or vr.get("version_end"):
                            display_range = []
                            if vr.get("version_start"):
                                display_range.append(f">{'=' if vr.get('version_start_type') == 'including' else ''}{vr.get('version_start')}")
                            if vr.get("version_end"):
                                display_range.append(f"<{'=' if vr.get('version_end_type') == 'including' else ''}{vr.get('version_end')}")
                            version_range_info = " AND ".join(display_range) if display_range else None
                            break

                if not version_range_info and llm_result["affected"]:
                    version_range_info = llm_reasoning[:50] + "..." if len(llm_reasoning) > 50 else llm_reasoning

                if not version_applicable:
                    logger.info(
                        f"✗ CVE {cve_id} does NOT affect version {version_filter}\n"
                        f"  Reason: {llm_reasoning}\n"
                        f"  Confidence: {llm_result['confidence']:.2f}"
                    )
                    continue
                else:
                    logger.info(
                        f"✓ CVE {cve_id} AFFECTS version {version_filter}\n"
                        f"  Reason: {llm_reasoning}\n"
                        f"  Confidence: {llm_result['confidence']:.2f}"
                    )

            # This CVE affects the target version - count it
            version_specific_count += 1

            # Count by severity
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

            # Add to notable if critical or high
            if severity in ["CRITICAL", "HIGH"] and len(notable_cves) < 10:
                # Build NVD source URL for this CVE
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                notable_cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "description": description[:200] + "..." if len(description) > 200 else description,
                    "patched": False,  # NVD doesn't provide patch status - AI will determine
                    "source": nvd_url,
                    "version_range": version_range_info,
                })

        # Sort notable by CVSS score
        notable_cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

        # Log filtering results
        if version_filter and version_filter not in ['latest', 'unknown']:
            logger.info(
                f"Version filtering: {total_raw_cves} total CVEs → {version_specific_count} affect version {version_filter} "
                f"({critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low)"
            )

        return {
            "total_cves": version_specific_count if version_filter else total_raw_cves,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "notable_cves": notable_cves[:5],  # Top 5
            "source_url": f"{self.base_url}?keywordSearch={vulnerabilities[0].get('cve', {}).get('id', '')}" if vulnerabilities else self.base_url,
            "version_filtered": bool(version_filter and version_filter not in ['latest', 'unknown']),
            "raw_cve_count": total_raw_cves,
        }

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty CVE result."""
        return {
            "total_cves": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "notable_cves": [],
            "source_url": self.base_url,
        }
