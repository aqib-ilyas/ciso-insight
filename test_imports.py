"""Quick test to verify all imports work correctly."""
import sys

print("Testing CISO Insight imports...")
print("-" * 50)

# Test core dependencies
try:
    import fastapi
    print("✓ FastAPI imported successfully")
except ImportError as e:
    print(f"✗ FastAPI import failed: {e}")
    sys.exit(1)

try:
    import uvicorn
    print("✓ Uvicorn imported successfully")
except ImportError as e:
    print(f"✗ Uvicorn import failed: {e}")
    sys.exit(1)

try:
    import jinja2
    print("✓ Jinja2 imported successfully")
except ImportError as e:
    print(f"✗ Jinja2 import failed: {e}")
    sys.exit(1)

try:
    import openai
    print("✓ OpenAI imported successfully")
except ImportError as e:
    print(f"✗ OpenAI import failed: {e}")
    sys.exit(1)

try:
    import httpx
    print("✓ HTTPX imported successfully")
except ImportError as e:
    print(f"✗ HTTPX import failed: {e}")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    print("✓ BeautifulSoup4 imported successfully")
except ImportError as e:
    print(f"✗ BeautifulSoup4 import failed: {e}")
    sys.exit(1)

try:
    import aiosqlite
    print("✓ aiosqlite imported successfully")
except ImportError as e:
    print(f"✗ aiosqlite import failed: {e}")
    sys.exit(1)

# Test app modules
try:
    from app.config import settings
    print("✓ App config loaded successfully")
except ImportError as e:
    print(f"✗ App config import failed: {e}")
    sys.exit(1)

try:
    from app.models import Assessment, EntityResolution
    print("✓ App models imported successfully")
except ImportError as e:
    print(f"✗ App models import failed: {e}")
    sys.exit(1)

try:
    from app.database import db
    print("✓ Database module imported successfully")
except ImportError as e:
    print(f"✗ Database module import failed: {e}")
    sys.exit(1)

try:
    from app.collectors.nvd import NVDClient
    from app.collectors.cisa_kev import CISAKEVClient
    from app.collectors.scraper import SecurityScraper
    print("✓ Data collectors imported successfully")
except ImportError as e:
    print(f"✗ Data collectors import failed: {e}")
    sys.exit(1)

try:
    from app.ai.resolver import EntityResolver
    from app.ai.synthesizer import SecuritySynthesizer
    print("✓ AI services imported successfully")
except ImportError as e:
    print(f"✗ AI services import failed: {e}")
    sys.exit(1)

try:
    from app.main import app
    print("✓ FastAPI app imported successfully")
except ImportError as e:
    print(f"✗ FastAPI app import failed: {e}")
    sys.exit(1)

print("-" * 50)
print("✓ All imports successful!")
print("\nYou can now run the application with:")
print("  python -m uvicorn app.main:app --reload")
print("\nOr use the startup script:")
print("  run.bat (Windows)")
print("  bash run.sh (Linux/Mac)")
