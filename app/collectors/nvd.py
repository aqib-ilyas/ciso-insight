"""NVD CVE API client."""
import httpx
import logging
import asyncio
import re
import json
from typing import Dict, Any, List, Optional
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

    # --------------------------------------------------------------------- #
    # LLM FALLBACK – used only when we have NO structured version ranges
    # --------------------------------------------------------------------- #
    async def _llm_check_version_affected(
        self,
        cve_id: str,
        description: str,
        target_version: str,
        product_name: str,
        version_ranges: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Use LLM to determine if a CVE affects a specific version.
        This is used as a LAST RESORT when structured version ranges are
        missing or unclear.
        """
        version_info = ""
        if version_ranges:
            version_info = "Version ranges from NVD configuration:\n"
            for vr in version_ranges[:5]:
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
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert analyzing CVE version "
                            "applicability. Be precise and conservative."
                        ),
                    },
                    {"role": "user", "content": prompt},
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
                "reasoning": f"LLM check failed, assuming affected for safety: {str(e)}",
            }

    # --------------------------------------------------------------------- #
    # VERSION NORMALIZATION / RANGE LOGIC
    # --------------------------------------------------------------------- #
    def _normalize_version(self, version_str: str) -> Optional[pkg_version.Version]:
        """Normalize version string for comparison."""
        if not version_str or version_str.lower() in ["latest", "unknown", "*", "-"]:
            return None
        try:
            cleaned = version_str.strip().lstrip("v").lstrip("V")
            cleaned = cleaned.rstrip(".*")
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
        version_end_type: str = "including",
    ) -> bool:
        """
        Check if target version falls within affected range using pure CPE data.
        """
        target = self._normalize_version(target_version)
        if not target:
            return False

        if not version_start and not version_end:
            # No bounds at all → can't decide here.
            return False

        if version_start:
            start = self._normalize_version(version_start)
            if start:
                if version_start_type == "including":
                    if target < start:
                        return False
                else:  # excluding
                    if target <= start:
                        return False

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
        """
        Extract affected version ranges from CVE configurations (NVD 2.0 format).
        """
        version_ranges: List[Dict[str, Any]] = []

        try:
            configurations = cve_item.get("cve", {}).get("configurations", [])

            for config in configurations:
                nodes = config.get("nodes", [])

                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])

                    for cpe_match in cpe_matches:
                        if not cpe_match.get("vulnerable"):
                            continue

                        version_range: Dict[str, Any] = {
                            "cpe": cpe_match.get("criteria", ""),
                            "version_start": cpe_match.get("versionStartIncluding")
                            or cpe_match.get("versionStartExcluding"),
                            "version_start_type": "including"
                            if cpe_match.get("versionStartIncluding")
                            else "excluding",
                            "version_end": cpe_match.get("versionEndIncluding")
                            or cpe_match.get("versionEndExcluding"),
                            "version_end_type": "including"
                            if cpe_match.get("versionEndIncluding")
                            else "excluding",
                        }

                        has_version_info = False
                        cpe_parts = cpe_match.get("criteria", "").split(":")
                        if len(cpe_parts) >= 6:
                            cpe_version = cpe_parts[5]
                            if cpe_version and cpe_version not in ["*", "-"]:
                                version_range["exact_version"] = cpe_version
                                has_version_info = True

                        if version_range.get("version_start") or version_range.get("version_end"):
                            has_version_info = True

                        if has_version_info:
                            version_ranges.append(version_range)

        except Exception as e:
            logger.debug(f"Failed to extract version ranges: {e}")

        return version_ranges

    # --------------------------------------------------------------------- #
    # CPE / VENDOR HELPERS
    # --------------------------------------------------------------------- #
    def _extract_candidate_vendors(
        self,
        vulnerabilities: List[Dict[str, Any]],
        product_name: str,
        vendor_hint: Optional[str] = None,
    ) -> List[str]:
        """
        Extract canonical vendor names from CPE criteria in NVD response.
        We normalize product names and use vendor_hint only for tie-breaking.
        """
        if not vulnerabilities:
            return []

        normalized_product = re.sub(r"[^a-z0-9]+", "", product_name.lower())
        vendors = set()

        for vuln in vulnerabilities:
            configs = vuln.get("cve", {}).get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        crit = cpe_match.get("criteria") or ""
                        parts = crit.split(":")
                        # cpe:2.3:part:vendor:product:version:...
                        if len(parts) >= 6:
                            vendor = parts[3]
                            prod = parts[4]
                            norm_prod = re.sub(r"[^a-z0-9]+", "", prod.lower())
                            if norm_prod == normalized_product and vendor not in ["*", "-"]:
                                vendors.add(vendor)

        candidates = list(vendors)

        # If we have a vendor hint, try to prefer the closest match
        if vendor_hint and candidates:
            hint_norm = re.sub(r"[^a-z0-9]+", "", vendor_hint.lower())
            candidates.sort(
                key=lambda v: 0
                if re.sub(r"[^a-z0-9]+", "", v.lower()) == hint_norm
                else 1
            )

        return candidates

    def _build_cpe_name(
        self,
        vendor: str,
        product: str,
        version: Optional[str] = None,
    ) -> str:
        """
        Build a basic CPE 2.3 name for applications (part 'a').

        NOTE: we put '*' for version here and rely on _process_cve_data +
        version filtering to decide applicability. This avoids missing CVEs
        that are expressed as version ranges instead of exact version.
        """
        normalized_vendor = vendor.lower()
        normalized_product = re.sub(r"[^a-z0-9_\-\.]+", "_", product.lower())
        cpe_version = version  # we filter by version ourselves
        return f"cpe:2.3:a:{normalized_vendor}:{normalized_product}:{cpe_version}:*:*:*:*:*:*:*"

    # --------------------------------------------------------------------- #
    # PUBLIC API
    # --------------------------------------------------------------------- #
    async def search_cve_by_id(self, cve_id: str, version: str) -> Dict[str, Any]:
        """Search for a specific CVE by ID."""
        try:
            params = {"cveId": cve_id}
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            await asyncio.sleep(self.rate_limit_delay)

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                logger.info(f"Searching NVD for CVE ID: {cve_id}")
                response = await client.get(self.base_url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()

            return await self._process_cve_data(data, version_filter=version, product_name="")

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for {cve_id}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error for {cve_id}: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"NVD search failed for {cve_id}: {str(e)}")
            return self._empty_result()

    async def search_cves(
        self,
        product_name: str,
        vendor_name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Search for CVEs related to a product and optionally filter by version.

        Flow:
        - Always do an initial keyword search using product + vendor hint.
        - From that response, extract canonical vendor names from CPE.
        - If any canonical vendors exist:
            * Build cpeName queries for vendor+product (version-agnostic).
            * Merge those results.
        - Then run _process_cve_data with version_filter for version-specific
          applicability. The LLM is only used when there is no version data.
        """
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                # Stage 1: initial keyword search
                search_terms = [product_name]
                if vendor_name:
                    search_terms.append(vendor_name)

                params = {
                    "keywordSearch": product_name,
                    "resultsPerPage": 200,
                }
                # params = {
                #     "keywordSearch": " ".join(product_name),
                #     "resultsPerPage": 200,
                # }

                await asyncio.sleep(self.rate_limit_delay)
                logger.info(f"Initial NVD search for: {product_name}")
                resp = await client.get(self.base_url, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    logger.info("No CVEs from initial keyword search.")
                    return self._empty_result()

                # If we don't care about version, just process keyword results.
                if not version:
                    return await self._process_cve_data(
                        data,
                        version_filter=version,
                        product_name=product_name,
                    )

                # Stage 2: infer canonical vendor(s) from CPE
                candidate_vendors = self._extract_candidate_vendors(
                    vulnerabilities,
                    product_name=product_name,
                    vendor_hint=vendor_name,
                )

                if not candidate_vendors:
                    logger.info(
                        "No canonical vendors inferred from CPE; using keyword search data."
                    )
                    return await self._process_cve_data(
                        data,
                        version_filter=version,
                        product_name=product_name,
                    )

                logger.info(f"Inferred candidate vendors from CPE: {candidate_vendors}")

                all_vulns: List[Dict[str, Any]] = []

                # For each canonical vendor, do a cpeName-based query
                for vendor in candidate_vendors:
                    cpe_name = self._build_cpe_name(vendor, product_name, version)
                    cpe_params = {
                        "cpeName": cpe_name,
                        "resultsPerPage": 200,
                    }
                    await asyncio.sleep(self.rate_limit_delay)
                    logger.info(f"NVD cpeName search for: {cpe_name}")
                    cpe_resp = await client.get(
                        self.base_url, params=cpe_params, headers=headers
                    )
                    cpe_resp.raise_for_status()
                    cpe_data = cpe_resp.json()
                    all_vulns.extend(cpe_data.get("vulnerabilities", []))

                if not all_vulns:
                    logger.info(
                        "cpeName searches returned no results."
                    )

                # Build a synthetic NVD-like response with merged vulnerabilities
                merged_data = {"vulnerabilities": all_vulns}

                return await self._process_cve_data(
                    merged_data,
                    version_filter=version,
                    product_name=product_name,
                )

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for {product_name}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"NVD search failed: {str(e)}")
            return self._empty_result()

    # --------------------------------------------------------------------- #
    # CORE PROCESSING
    # --------------------------------------------------------------------- #
    async def _process_cve_data(
        self,
        data: Dict[str, Any],
        version_filter: Optional[str] = None,
        product_name: str = "",
    ) -> Dict[str, Any]:
        """
        Process NVD API response and (optionally) filter by version.

        Version logic:
        - If version_filter is provided:
            1) Try to use structured CPE version ranges via _is_version_affected.
            2) ONLY if no ranges exist, call the LLM as fallback.
        """
        vulnerabilities = data.get("vulnerabilities", [])
        total_raw_cves = len(vulnerabilities)

        if total_raw_cves == 0:
            return self._empty_result()

        critical_count = high_count = medium_count = low_count = 0
        notable_cves: List[Dict[str, Any]] = []
        version_specific_count = 0
        all_cve_ids: List[str] = []  # Track ALL CVE IDs that pass version filtering

        logger.info(
            f"Processing {total_raw_cves} CVEs (version filter: {version_filter})"
        )

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # CVSS severity
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = 0.0
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    cvss_data = metrics[metric_type][0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    break

            # English description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            version_applicable = True
            version_range_info: Optional[str] = None
            llm_reasoning: Optional[str] = None

            if version_filter and version_filter not in ["latest", "unknown"]:
                # Try structured version ranges first
                version_ranges = self._extract_affected_versions(vuln)

                if version_ranges:
                    applicable = False
                    for vr in version_ranges:
                        if self._is_version_affected(
                            target_version=version_filter,
                            version_start=vr.get("version_start"),
                            version_start_type=vr.get("version_start_type", "including"),
                            version_end=vr.get("version_end"),
                            version_end_type=vr.get("version_end_type", "including"),
                        ):
                            applicable = True
                            # Build simple range info
                            if vr.get("exact_version"):
                                version_range_info = f"v{vr['exact_version']}"
                            else:
                                display = []
                                if vr.get("version_start"):
                                    display.append(
                                        f">{'=' if vr.get('version_start_type') == 'including' else ''}{vr.get('version_start')}"
                                    )
                                if vr.get("version_end"):
                                    display.append(
                                        f"<{'=' if vr.get('version_end_type') == 'including' else ''}{vr.get('version_end')}"
                                    )
                                version_range_info = " AND ".join(display) if display else None
                            break

                    version_applicable = applicable
                    if not version_applicable:
                        logger.info(
                            f"✗ CVE {cve_id} does NOT affect version {version_filter} "
                            f"(structured CPE ranges)"
                        )
                        continue

                else:
                    # No structured ranges → LAST RESORT: ask LLM
                    llm_result = await self._llm_check_version_affected(
                        cve_id=cve_id,
                        description=description,
                        target_version=version_filter,
                        product_name=product_name,
                        version_ranges=[],
                    )
                    version_applicable = llm_result["affected"]
                    llm_reasoning = llm_result["reasoning"]

                    if not version_applicable:
                        logger.info(
                            f"✗ CVE {cve_id} does NOT affect version {version_filter}\n"
                            f"  Reason (LLM): {llm_reasoning}\n"
                            f"  Confidence: {llm_result['confidence']:.2f}"
                        )
                        continue
                    else:
                        logger.info(
                            f"✓ CVE {cve_id} AFFECTS version {version_filter}\n"
                            f"  Reason (LLM): {llm_reasoning}\n"
                            f"  Confidence: {llm_result['confidence']:.2f}"
                        )
                        version_range_info = (
                            llm_reasoning[:50] + "..."
                            if llm_reasoning and len(llm_reasoning) > 50
                            else llm_reasoning
                        )

            # CVE is considered applicable (or no version filter)
            version_specific_count += 1
            all_cve_ids.append(cve_id)  # Track this CVE ID

            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

            if severity in ["CRITICAL", "HIGH"] and len(notable_cves) < 10:
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                notable_cves.append(
                    {
                        "id": cve_id,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "description": description[:200] + "..."
                        if len(description) > 200
                        else description,
                        "patched": False,  # patch info is handled elsewhere / by AI
                        "source": nvd_url,
                        "version_range": version_range_info,
                    }
                )

        notable_cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

        if version_filter and version_filter not in ["latest", "unknown"]:
            logger.info(
                f"Version filtering: {total_raw_cves} total CVEs → {version_specific_count} "
                f"affect version {version_filter} "
                f"({critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low)"
            )

        return {
            "total_cves": version_specific_count if version_filter else total_raw_cves,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "notable_cves": notable_cves[:5],
            "all_cve_ids": all_cve_ids,  # ALL CVE IDs that passed version filtering
            "source_url": self.base_url,
            "version_filtered": bool(
                version_filter and version_filter not in ["latest", "unknown"]
            ),
            "raw_cve_count": total_raw_cves,
        }

    # --------------------------------------------------------------------- #
    # UTIL
    # --------------------------------------------------------------------- #
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
