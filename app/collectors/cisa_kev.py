"""CISA Known Exploited Vulnerabilities (KEV) catalog checker."""
import httpx
import logging
from typing import List, Dict, Any
from ..config import settings

logger = logging.getLogger(__name__)


class CISAKEVClient:
    """Client for CISA KEV catalog."""

    def __init__(self):
        self.kev_url = settings.CISA_KEV_URL
        self._kev_cache = None

    async def load_kev_catalog(self) -> List[Dict[str, Any]]:
        """Load the CISA KEV catalog."""
        if self._kev_cache is not None:
            return self._kev_cache

        try:
            async with httpx.AsyncClient(timeout=settings.API_TIMEOUT) as client:
                logger.info("Fetching CISA KEV catalog")
                response = await client.get(self.kev_url)
                response.raise_for_status()
                data = response.json()

            self._kev_cache = data.get("vulnerabilities", [])
            logger.info(f"Loaded {len(self._kev_cache)} KEV entries")
            return self._kev_cache

        except Exception as e:
            logger.error(f"Failed to load CISA KEV catalog: {str(e)}")
            return []

    async def check_cves_in_kev(self, cve_ids: List[str]) -> Dict[str, Any]:
        """
        Check if CVE IDs are in the CISA KEV catalog.

        Args:
            cve_ids: List of CVE IDs to check

        Returns:
            Dict with KEV status and matched CVEs
        """
        if not cve_ids:
            return {
                "in_kev": False,
                "kev_count": 0,
                "kev_cves": [],
            }

        kev_catalog = await self.load_kev_catalog()

        # Build set of KEV CVE IDs for fast lookup
        kev_cve_set = {vuln.get("cveID") for vuln in kev_catalog}

        # Find matches
        matched_cves = []
        for cve_id in cve_ids:
            if cve_id in kev_cve_set:
                # Find full entry
                for vuln in kev_catalog:
                    if vuln.get("cveID") == cve_id:
                        matched_cves.append({
                            "id": cve_id,
                            "name": vuln.get("vulnerabilityName", ""),
                            "date_added": vuln.get("dateAdded", ""),
                            "required_action": vuln.get("requiredAction", ""),
                            "due_date": vuln.get("dueDate", ""),
                        })
                        break

        return {
            "in_kev": len(matched_cves) > 0,
            "kev_count": len(matched_cves),
            "kev_cves": matched_cves,
        }

    async def check_product_in_kev(self, product_name: str, vendor_name: str = None) -> Dict[str, Any]:
        """
        Check if a product has any vulnerabilities in KEV.

        Args:
            product_name: Product name to search for
            vendor_name: Optional vendor name

        Returns:
            Dict with KEV status and matched vulnerabilities
        """
        kev_catalog = await self.load_kev_catalog()

        search_terms = [product_name.lower()]
        if vendor_name:
            search_terms.append(vendor_name.lower())

        matched = []
        for vuln in kev_catalog:
            vuln_name = vuln.get("vulnerabilityName", "").lower()
            product = vuln.get("product", "").lower()
            vendor = vuln.get("vendorProject", "").lower()

            # Check if any search term matches
            for term in search_terms:
                if term in vuln_name or term in product or term in vendor:
                    matched.append({
                        "cve_id": vuln.get("cveID", ""),
                        "name": vuln.get("vulnerabilityName", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "date_added": vuln.get("dateAdded", ""),
                    })
                    break

        return {
            "in_kev": len(matched) > 0,
            "kev_count": len(matched),
            "kev_vulnerabilities": matched[:10],  # Limit to 10
        }
