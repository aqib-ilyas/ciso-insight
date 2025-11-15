"""Entity resolution using OpenAI."""
import logging
import json
from openai import AsyncOpenAI
from typing import Dict, Any
from ..config import settings
from ..models import EntityResolution

logger = logging.getLogger(__name__)


class EntityResolver:
    """Resolve product entities using AI."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def resolve_entity(self, user_input: str) -> EntityResolution:
        """
        Resolve entity from user input.

        Args:
            user_input: Product name or URL from user

        Returns:
            EntityResolution with normalized product info
        """
        system_prompt = """You are an expert at identifying and resolving software product entities.

Your task is to take user input (which may be a product name, URL, or vague description) and return structured information about the product.

CRITICAL REQUIREMENTS:
1. Handle non-Latin characters (Chinese, Japanese, Korean, etc.) correctly
2. Normalize product names to their official spelling
3. Identify the correct vendor/company
4. Find the official website
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
- Other (specify)

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
            )
