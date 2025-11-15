"""NVD CVE API client."""
import httpx
import logging
import asyncio
from typing import Dict, Any, List
from ..config import settings

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for NIST NVD CVE API."""

    def __init__(self):
        self.base_url = settings.NVD_BASE_URL
        self.api_key = settings.NVD_API_KEY
        self.rate_limit_delay = settings.NVD_RATE_LIMIT

    async def search_cves(self, product_name: str, vendor_name: str = None) -> Dict[str, Any]:
        """
        Search for CVEs related to a product.

        Returns:
            Dict containing CVE statistics and notable entries
        """
        try:
            # Build search query
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

            return self._process_cve_data(data)

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for {product_name}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"NVD search failed: {str(e)}")
            return self._empty_result()

    def _process_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process NVD API response."""
        vulnerabilities = data.get("vulnerabilities", [])
        total_cves = len(vulnerabilities)

        if total_cves == 0:
            return self._empty_result()

        # Count by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        notable_cves = []

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

            # Count by severity
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

            # Get description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Add to notable if critical or high
            if severity in ["CRITICAL", "HIGH"] and len(notable_cves) < 5:
                notable_cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "description": description[:200] + "..." if len(description) > 200 else description,
                    "cvss_score": cvss_score,
                    "published": cve.get("published", ""),
                })

        # Sort notable by CVSS score
        notable_cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

        return {
            "total_cves": total_cves,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "notable_cves": notable_cves[:5],  # Top 5
            "source_url": f"{self.base_url}?keywordSearch={vulnerabilities[0].get('cve', {}).get('id', '')}",
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
