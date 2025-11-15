"""Configuration management for CISO Insight."""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings."""

    # OpenAI
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = "gpt-4o"

    # NVD API
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # CISA KEV
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Caching
    CACHE_TTL_HOURS: int = int(os.getenv("CACHE_TTL_HOURS", "24"))
    DATABASE_PATH: str = "ciso_insight.db"

    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # HTTP Settings
    HTTP_TIMEOUT: int = 5  # seconds for web scraping
    API_TIMEOUT: int = 30  # seconds for API calls
    NVD_RATE_LIMIT: float = 0.2  # 5 requests per second

    # User Agent for scraping
    USER_AGENT: str = "CISO-Insight/1.0 (Security Assessment Tool)"


settings = Settings()
