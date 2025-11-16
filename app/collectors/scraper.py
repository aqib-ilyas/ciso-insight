"""Web scraper for security and compliance information."""
import httpx
import logging
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from ..config import settings

logger = logging.getLogger(__name__)


class SecurityScraper:
    """Scraper for security-related web content."""

    def __init__(self):
        self.timeout = settings.HTTP_TIMEOUT
        self.user_agent = settings.USER_AGENT

    async def verify_domain(self, domain: str) -> bool:
        """
        Verify that a domain exists and is accessible.

        Args:
            domain: Domain to verify (e.g., "slack.com" or "https://slack.com")

        Returns:
            True if domain is accessible, False otherwise
        """
        # Normalize domain
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"

        try:
            headers = {"User-Agent": self.user_agent}
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(domain, headers=headers)
                response.raise_for_status()
                logger.info(f"Domain verified: {domain}")
                return True
        except Exception as e:
            logger.error(f"Domain verification failed for {domain}: {str(e)}")
            return False

    async def scrape_security_pages(self, domain: str) -> Dict[str, Any]:
        """
        Scrape security-related pages from a domain.

        Args:
            domain: Domain to scrape (e.g., "slack.com")

        Returns:
            Dict containing scraped security information
        """
        # Normalize domain
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"

        base_domain = urlparse(domain).netloc or domain

        # Common security page paths to try (including homepage)
        security_paths = [
            "/",  # Homepage
            "/security",
            "/trust",
            "/security/advisories",
            "/psirt",
            "/security-advisories",
            "/trust-center",
            "/compliance",
            "/privacy",
            "/responsible-disclosure",
            "/bug-bounty",
            "/.well-known/security.txt",
        ]

        results = {
            "security_pages_found": [],
            "bug_bounty": None,
            "security_contact": None,
            "certifications": [],
            "compliance_mentions": [],
            "sources": [],
        }

        for path in security_paths:
            url = urljoin(domain, path)
            page_data = await self._fetch_page(url)

            if page_data:
                results["security_pages_found"].append({
                    "url": url,
                    "title": page_data.get("title", ""),
                    "path": path,
                })
                results["sources"].append(url)

                # Extract relevant information
                content = page_data.get("text", "").lower()

                # Check for bug bounty
                if "bug bounty" in content or "hackerone" in content or "bugcrowd" in content:
                    results["bug_bounty"] = url

                # Check for security contact
                if "security@" in content or "psirt@" in content:
                    results["security_contact"] = url

                # Check for certifications
                certs = self._extract_certifications(content)
                results["certifications"].extend(certs)

                # Check for compliance mentions
                compliance = self._extract_compliance(content)
                results["compliance_mentions"].extend(compliance)

        # Deduplicate
        results["certifications"] = list(set(results["certifications"]))
        results["compliance_mentions"] = list(set(results["compliance_mentions"]))
        results["sources"] = list(set(results["sources"]))

        return results

    async def _fetch_page(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse a web page."""
        try:
            headers = {"User-Agent": self.user_agent}

            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()

                # Parse HTML
                soup = BeautifulSoup(response.text, "html.parser")

                # Remove script and style elements
                for script in soup(["script", "style"]):
                    script.decompose()

                # Get text
                text = soup.get_text(separator=" ", strip=True)

                # Get title
                title = soup.title.string if soup.title else ""

                return {
                    "url": url,
                    "title": title,
                    "text": text,
                    "html": response.text,
                }

        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                logger.debug(f"HTTP error {e.response.status_code} for {url}")
            return None
        except httpx.TimeoutException:
            logger.debug(f"Timeout fetching {url}")
            return None
        except Exception as e:
            logger.debug(f"Error fetching {url}: {str(e)}")
            return None

    def _extract_certifications(self, text: str) -> List[str]:
        """Extract certification mentions from text."""
        certs = []
        cert_keywords = {
            "soc 2": "SOC2",
            "soc2": "SOC2",
            "iso 27001": "ISO27001",
            "iso27001": "ISO27001",
            "iso 9001": "ISO9001",
            "pci dss": "PCI-DSS",
            "hipaa": "HIPAA",
            "gdpr": "GDPR",
            "ccpa": "CCPA",
            "fedramp": "FedRAMP",
        }

        for keyword, cert_name in cert_keywords.items():
            if keyword in text:
                certs.append(cert_name)

        return certs

    def _extract_compliance(self, text: str) -> List[str]:
        """Extract compliance framework mentions."""
        compliance = []
        frameworks = [
            "NIST",
            "CIS",
            "CSA",
            "SOC 2",
            "ISO 27001",
            "GDPR",
            "CCPA",
            "HIPAA",
            "PCI DSS",
        ]

        for framework in frameworks:
            if framework.lower() in text:
                compliance.append(framework)

        return compliance

    async def check_terms_and_privacy(self, domain: str) -> Dict[str, Any]:
        """Check for Terms of Service and Privacy Policy."""
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"

        paths = [
            "/terms",
            "/tos",
            "/terms-of-service",
            "/privacy",
            "/privacy-policy",
            "/legal/privacy",
            "/legal/terms",
        ]

        results = {
            "terms_url": None,
            "privacy_url": None,
        }

        for path in paths:
            url = urljoin(domain, path)
            page_data = await self._fetch_page(url)

            if page_data:
                title = page_data.get("title", "").lower()
                text = page_data.get("text", "").lower()

                if "terms" in path or "tos" in path:
                    if "terms of service" in text or "terms and conditions" in text:
                        results["terms_url"] = url
                elif "privacy" in path:
                    if "privacy policy" in text or "privacy notice" in text:
                        results["privacy_url"] = url

        return results
