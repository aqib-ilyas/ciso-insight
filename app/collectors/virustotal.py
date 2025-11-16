"""VirusTotal API client for domain and URL reputation analysis."""
import httpx
import logging
import asyncio
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ..config import settings

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Client for VirusTotal API - domain/URL reputation and threat intelligence."""

    def __init__(self):
        self.base_url = settings.VIRUSTOTAL_BASE_URL
        self.api_key = settings.VIRUSTOTAL_API_KEY

    async def analyze_file_hash(self, sha1: str) -> Dict[str, Any]:
        """
        Analyze file by SHA1 hash to get version and metadata.

        Args:
            sha1: SHA1 hash of the file

        Returns:
            Dict containing version and file metadata
        """
        if not sha1 or not self.api_key:
            logger.warning("VirusTotal file analysis skipped: missing SHA1 or API key")
            return self._empty_file_result()

        try:
            logger.info(f"Analyzing file hash on VirusTotal: {sha1}")

            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                # Get file report
                response = await client.get(
                    f"{self.base_url}/files/{sha1}",
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

            return self._process_file_data(data, sha1)

        except httpx.TimeoutException:
            logger.error(f"VirusTotal API timeout for file hash: {sha1}")
            return self._empty_file_result()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.info(f"File hash not found in VirusTotal: {sha1}")
                return self._empty_file_result(not_found=True)
            logger.error(f"VirusTotal API error: {e.response.status_code}")
            return self._empty_file_result()
        except Exception as e:
            logger.error(f"VirusTotal file analysis failed: {str(e)}")
            return self._empty_file_result()

    def _process_file_data(self, data: Dict[str, Any], sha1: str) -> Dict[str, Any]:
        """Process VirusTotal file report."""
        attributes = data.get("data", {}).get("attributes", {})

        if not attributes:
            return self._empty_file_result()

        version = "unknown"
        # Extract version information
        # Try signature info
        if version == "unknown":
            signature_info = attributes.get("signature_info", {})
            if signature_info:
                version = signature_info.get("file version", "unknown")

        if version == "unknown":
            # Try to get version from PE info (for Windows executables)
            pe_info = attributes.get("pe_info", {})
            if pe_info:
                version_info = pe_info.get("version_info", {})
                if version_info:
                    # Try ProductVersion first, then FileVersion
                    version = (
                        version_info.get("ProductVersion") or
                        version_info.get("FileVersion") or
                        "unknown"
                    )

        # Try tags or names that might contain version
        if version == "unknown":
            names = attributes.get("names", [])
            for name in names:
                # Look for version patterns like "v1.2.3" or "1.2.3"
                import re
                version_match = re.search(r'v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', name)
                if version_match:
                    version = version_match.group(1)
                    break

        # Get file metadata
        file_name = attributes.get("meaningful_name") or attributes.get("names", ["unknown"])[0]
        file_type = attributes.get("type_description", "unknown")

        # Get detection stats
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)

        logger.info(
            f"VirusTotal file analysis for {sha1}: "
            f"version={version}, name={file_name}, malicious={malicious}"
        )

        return {
            "analyzed": True,
            "sha1": sha1,
            "version": version,
            "file_name": file_name,
            "file_type": file_type,
            "malicious_detections": malicious,
            "virustotal_url": f"https://www.virustotal.com/gui/file/{sha1}",
        }

    def _empty_file_result(self, not_found: bool = False) -> Dict[str, Any]:
        """Return empty file analysis result."""
        return {
            "analyzed": False,
            "not_found": not_found,
            "version": "unknown",
            "sha1": None,
            "file_name": None,
            "file_type": None,
            "malicious_detections": 0,
            "virustotal_url": "",
        }

    async def analyze_domain(self, url: str) -> Dict[str, Any]:
        """
        Analyze domain reputation using VirusTotal.

        Args:
            url: Official website URL (e.g., "https://slack.com")

        Returns:
            Dict containing domain reputation data
        """
        if not url or not self.api_key:
            logger.warning("VirusTotal analysis skipped: missing URL or API key")
            return self._empty_result()

        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path

            if not domain:
                logger.warning(f"Could not extract domain from URL: {url}")
                return self._empty_result()

            # Remove www. prefix if present
            domain = domain.replace("www.", "")

            logger.info(f"Analyzing domain reputation on VirusTotal: {domain}")

            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }

            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                # Get domain report
                response = await client.get(
                    f"{self.base_url}/domains/{domain}",
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

            return self._process_domain_data(data, domain)

        except httpx.TimeoutException:
            logger.error(f"VirusTotal API timeout for {url}")
            return self._empty_result()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.info(f"Domain not found in VirusTotal: {domain}")
                return self._empty_result(domain, not_found=True)
            logger.error(f"VirusTotal API error: {e.response.status_code}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {str(e)}")
            return self._empty_result()

    def _process_domain_data(self, data: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Process VirusTotal domain report."""
        attributes = data.get("data", {}).get("attributes", {})

        if not attributes:
            return self._empty_result(domain)

        # Get reputation score
        reputation = attributes.get("reputation", 0)

        # Get last analysis stats
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        # Get categories
        categories = attributes.get("categories", {})

        # Get popularity ranks
        popularity_ranks = attributes.get("popularity_ranks", {})

        # Calculate safety score
        safety_score = "unknown"
        has_detections = malicious > 0 or suspicious > 0

        if has_detections:
            if malicious >= 3:
                safety_score = "high_risk"
            elif malicious > 0 or suspicious >= 5:
                safety_score = "medium_risk"
            else:
                safety_score = "low_risk"
        elif harmless > 0 and reputation > -10:
            safety_score = "clean"
        elif total_engines > 0:
            safety_score = "clean"

        # Get last analysis date
        last_analysis_date = attributes.get("last_analysis_date", 0)

        # Get whois info
        whois = attributes.get("whois", "")
        creation_date = attributes.get("creation_date", 0)

        result = {
            "domain": domain,
            "analyzed": True,
            "reputation_score": reputation,
            "safety_score": safety_score,
            "detections": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines,
            },
            "categories": list(categories.values()) if categories else [],
            "popularity_ranks": popularity_ranks,
            "last_analysis_date": last_analysis_date,
            "creation_date": creation_date,
            "has_security_issues": has_detections,
            "virustotal_url": f"https://www.virustotal.com/gui/domain/{domain}",
        }

        logger.info(
            f"VirusTotal analysis for {domain}: {safety_score}, "
            f"{malicious}/{total_engines} malicious detections, "
            f"reputation: {reputation}"
        )

        return result

    def _empty_result(self, domain: str = "unknown", not_found: bool = False) -> Dict[str, Any]:
        """Return empty VirusTotal result."""
        return {
            "domain": domain,
            "analyzed": False,
            "not_found": not_found,
            "reputation_score": 0,
            "safety_score": "unknown",
            "detections": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
            },
            "categories": [],
            "popularity_ranks": {},
            "last_analysis_date": 0,
            "creation_date": 0,
            "has_security_issues": False,
            "virustotal_url": "",
        }
