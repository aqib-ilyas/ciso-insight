"""Entity resolution using OpenAI."""
import logging
import json
from openai import AsyncOpenAI
from typing import Dict, Any
from ..config import settings
from ..models import EntityResolution
from ..collectors.product_database import ProductDatabase
from ..collectors.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)


class EntityResolver:
    """Resolve product entities using AI."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL
        self.product_db = ProductDatabase()
        self.vt_client = VirusTotalClient()

    async def resolve_entity(self, user_input: str, user_version: str = None) -> EntityResolution:
        """
        Resolve entity from user input with version priority logic.

        Version Priority:
        1. User-provided version (highest priority)
        2. SHA1 from database → VirusTotal version detection
        3. Latest version auto-detection (lowest priority)

        Args:
            user_input: Product name or URL from user
            user_version: Optional version provided by user

        Returns:
            EntityResolution with normalized product info and version
        """
        # Step 1: Check product database for SHA1 hash
        db_entry = self.product_db.lookup_product(user_input)

        # Clean user version input
        if user_version:
            user_version = user_version.strip()
            if not user_version:
                user_version = None

        system_prompt = """You are an expert at identifying and resolving software product entities.

Your task is to take user input (which may be a product name, URL, or vague description) and return structured information about the product.

CRITICAL REQUIREMENTS:
1. Handle non-Latin characters (Chinese, Japanese, Korean, etc.) correctly
2. Normalize product names to their official spelling (e.g., "docker" → "Docker", "vscode" → "Visual Studio Code")
3. Identify the correct vendor/company (use official company name, not abbreviations). 
4. Find the official website (must be HTTPS, primary domain only)
5. Categorize the product accurately
6. Provide a brief description

CATEGORY TAXONOMY (choose the most specific):
- Password Manager
- Remote Access Tool
- File Sharing / Cloud Storage
- GenAI Tool / AI Assistant
- SaaS CRM
- Endpoint Security Agent
- Gaming Platform
- Security Tool
- Productivity Suite
- Media Tool / Player
- Compression Tool
- Developer Tool
- Web Browser
- Communication Tool
- Database System
- Virtualization / Container Platform
- Other (specify)

EXAMPLES:
Input: "docker"
Output: {
  "product_name": "Docker",
  "vendor_name": "Docker Inc",
  "official_website": "https://www.docker.com",
  "category": "Virtualization / Container Platform",
  "description": "Containerization platform for building, shipping, and running distributed applications."
}

Input: "https://github.com/microsoft/vscode"
Output: {
  "product_name": "Visual Studio Code",
  "vendor_name": "Microsoft Corporation",
  "official_website": "https://code.visualstudio.com",
  "category": "Developer Tool",
  "description": "Free source-code editor with debugging, Git integration, and extensions support."
}

Input: "1password"
Output: {
  "product_name": "1Password",
  "vendor_name": "1Password",
  "official_website": "https://1password.com",
  "category": "Password Manager",
  "description": "Password manager and digital vault for storing credentials and sensitive information."
}

Return ONLY valid JSON in this exact format:
{
    "product_name": "Official Product Name",
    "vendor_name": "Company/Vendor Name",
    "official_website": "https://official-domain.com",
    "category": "Category from taxonomy",
    "description": "Brief 1-2 sentence description of what the product does and who uses it"
}

If you cannot confidently identify the product, set product_name to "UNKNOWN" and explain in description."""

        user_prompt = f"""Resolve this entity: {user_input}

Provide structured JSON response."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            data = json.loads(content)

            logger.info(f"Resolved entity: {data.get('product_name')}")

            # Step 2: Version Resolution with Priority Logic
            version_source = "unknown"

            # PRIORITY 1: User-provided version (highest)
            if user_version:
                data['version'] = user_version
                data['sha1'] = None
                version_source = "user-provided"
                logger.info(
                    f"Using user-provided version: {user_version} for "
                    f"{data.get('product_name')}"
                )

            # PRIORITY 2: SHA1 from database → VirusTotal
            elif db_entry:
                sha1 = db_entry['sha1']
                data['sha1'] = sha1

                logger.info(f"Getting version from VirusTotal for SHA1: {sha1}")
                vt_file_data = await self.vt_client.analyze_file_hash(sha1)

                if vt_file_data.get('analyzed') and vt_file_data.get('version') != 'unknown':
                    data['version'] = vt_file_data['version']
                    version_source = "virustotal-sha1"
                    logger.info(
                        f"Got version {vt_file_data['version']} from VirusTotal for "
                        f"{data.get('product_name')} (SHA1: {sha1[:12]}...)"
                    )
                else:
                    # Try to get latest version
                    data['version'] = await self._get_latest_version(
                        data.get('product_name'),
                        data.get('vendor_name', ''),
                        data.get('official_website', '')
                    )
                    version_source = "auto-detected-latest"
                    logger.warning(
                        f"Could not get version from VirusTotal, using auto-detected: "
                        f"{data['version']}"
                    )

            # PRIORITY 3: Auto-detect latest version (lowest)
            else:
                data['sha1'] = None
                data['version'] = await self._get_latest_version(
                    data.get('product_name'),
                    data.get('vendor_name', ''),
                    data.get('official_website', '')
                )
                version_source = "auto-detected-latest"
                logger.info(
                    f"No SHA1 found, using auto-detected version: {data['version']} "
                    f"for {data.get('product_name')}"
                )

            # Store version source for transparency
            logger.info(
                f"Final version resolution: {data['version']} (source: {version_source})"
            )

            return EntityResolution(**data)

        except Exception as e:
            logger.error(f"Entity resolution failed: {str(e)}")
            # Return unknown entity
            return EntityResolution(
                product_name="UNKNOWN",
                vendor_name="Unknown",
                official_website="",
                category="Other",
                description=f"Could not resolve entity from input: {user_input}",
                version="latest",
                sha1=None,
            )

    async def _get_latest_version(self, product_name: str, vendor: str = "", website: str = "") -> str:
        """
        Multi-source version detection with fallback chain.

        Priority:
        1. GitHub Releases API (if website is GitHub)
        2. Package Registry APIs (npm, PyPI, Docker Hub, etc.)
        3. Vendor website meta tags
        4. Fallback to "latest"

        Args:
            product_name: Product name to search for
            vendor: Vendor name for better matching
            website: Official website URL

        Returns:
            Version string or "latest"
        """
        try:
            logger.info(f"Auto-detecting latest version for {product_name}")

            # Source 1: GitHub Releases API
            if website and "github.com" in website:
                version = await self._get_github_latest_version(website)
                if version != "latest":
                    logger.info(f"Found version {version} from GitHub releases")
                    return version

            # Source 2: Package Registries
            version = await self._check_package_registries(product_name)
            if version != "latest":
                logger.info(f"Found version {version} from package registry")
                return version

            # Source 3: Vendor website scraping (basic)
            if website:
                version = await self._scrape_vendor_version(website)
                if version != "latest":
                    logger.info(f"Found version {version} from vendor website")
                    return version

            logger.warning(f"Could not auto-detect version for {product_name}, using 'latest'")
            return "latest"

        except Exception as e:
            logger.error(f"Failed to auto-detect version for {product_name}: {str(e)}")
            return "latest"

    async def _get_github_latest_version(self, github_url: str) -> str:
        """Get latest release from GitHub API."""
        try:
            import re
            import httpx

            # Extract owner/repo from URL
            match = re.search(r'github\.com/([^/]+)/([^/]+)', github_url)
            if not match:
                return "latest"

            owner, repo = match.groups()
            repo = repo.rstrip('/')

            api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(api_url)
                if response.status_code == 200:
                    data = response.json()
                    tag = data.get('tag_name', '')
                    # Remove 'v' prefix if present
                    version = tag.lstrip('v').lstrip('V')
                    return version if version else "latest"

            return "latest"

        except Exception as e:
            logger.debug(f"GitHub API lookup failed: {str(e)}")
            return "latest"

    async def _check_package_registries(self, product_name: str) -> str:
        """Check common package registries for version."""
        try:
            import httpx

            # Normalize product name
            package_name = product_name.lower().replace(" ", "-")

            # Try npm registry
            try:
                npm_url = f"https://registry.npmjs.org/{package_name}/latest"
                async with httpx.AsyncClient(timeout=5) as client:
                    response = await client.get(npm_url)
                    if response.status_code == 200:
                        data = response.json()
                        version = data.get('version')
                        if version:
                            logger.debug(f"Found npm package: {package_name}@{version}")
                            return version
            except:
                pass

            # Try PyPI registry
            try:
                pypi_url = f"https://pypi.org/pypi/{package_name}/json"
                async with httpx.AsyncClient(timeout=5) as client:
                    response = await client.get(pypi_url)
                    if response.status_code == 200:
                        data = response.json()
                        version = data.get('info', {}).get('version')
                        if version:
                            logger.debug(f"Found PyPI package: {package_name}@{version}")
                            return version
            except:
                pass

            # Try Docker Hub
            try:
                docker_url = f"https://hub.docker.com/v2/repositories/library/{package_name}/tags?page_size=1"
                async with httpx.AsyncClient(timeout=5) as client:
                    response = await client.get(docker_url)
                    if response.status_code == 200:
                        data = response.json()
                        results = data.get('results', [])
                        if results and results[0].get('name') not in ['latest', 'stable']:
                            version = results[0].get('name')
                            logger.debug(f"Found Docker image: {package_name}:{version}")
                            return version
            except:
                pass

            return "latest"

        except Exception as e:
            logger.debug(f"Package registry lookup failed: {str(e)}")
            return "latest"

    async def _scrape_vendor_version(self, website: str) -> str:
        """Extract version from vendor website meta tags or content."""
        try:
            import httpx
            import re

            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(website, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })

                if response.status_code != 200:
                    return "latest"

                html = response.text

                # Look for version in meta tags
                version_patterns = [
                    r'<meta\s+name=["\']version["\']\s+content=["\']([^"\']+)["\']',
                    r'<meta\s+property=["\']og:version["\']\s+content=["\']([^"\']+)["\']',
                    r'version["\s:]+([0-9]+\.[0-9]+\.[0-9]+)',
                    r'v([0-9]+\.[0-9]+\.[0-9]+)',
                ]

                for pattern in version_patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        logger.debug(f"Found version {version} in website HTML")
                        return version

            return "latest"

        except Exception as e:
            logger.debug(f"Website scraping failed: {str(e)}")
            return "latest"
