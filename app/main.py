"""CISO Insight - Main FastAPI application."""
import logging
import time
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .database import db
from .models import Assessment
from .collectors.nvd import NVDClient
from .collectors.cisa_kev import CISAKEVClient
from .collectors.scraper import SecurityScraper
from .ai.resolver import EntityResolver
from .ai.synthesizer import SecuritySynthesizer

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting CISO Insight application")
    await db.init_db()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down CISO Insight application")


# Initialize FastAPI
app = FastAPI(
    title="CISO Insight",
    description="AI-powered security assessment for CISOs",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Initialize services
nvd_client = NVDClient()
kev_client = CISAKEVClient()
scraper = SecurityScraper()
resolver = EntityResolver()
synthesizer = SecuritySynthesizer()


def calculate_cache_age(timestamp: int) -> str:
    """Calculate human-readable cache age."""
    age_seconds = int(time.time()) - timestamp
    if age_seconds < 60:
        return "just now"
    elif age_seconds < 3600:
        minutes = age_seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif age_seconds < 86400:
        hours = age_seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    else:
        days = age_seconds // 86400
        return f"{days} day{'s' if days != 1 else ''} ago"


def get_trust_score_color(score: int) -> str:
    """Get color class for trust score."""
    if score >= 80:
        return "green"
    elif score >= 50:
        return "yellow"
    else:
        return "red"


# Add template filters
templates.env.filters["cache_age"] = calculate_cache_age
templates.env.filters["trust_color"] = get_trust_score_color


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Home page with search."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/assess")
async def assess_product(request: Request, input: str = Form(...)):
    """Process security assessment."""
    logger.info(f"Assessment request for: {input}")

    try:
        # Step 1: Entity Resolution
        entity = await resolver.resolve_entity(input)

        if entity.product_name == "UNKNOWN":
            return templates.TemplateResponse(
                "components/error.html",
                {
                    "request": request,
                    "error": "Could not identify the product. Please provide a more specific product name or URL.",
                },
            )

        # Check cache first
        cached = await db.get_assessment(entity.product_name)
        if cached:
            logger.info(f"Returning cached assessment for {entity.product_name}")
            assessment_data = cached["assessment"]
            assessment_data["metadata"]["cache_hit"] = True
            cache_age = calculate_cache_age(cached["timestamp"])

            return templates.TemplateResponse(
                "assessment.html",
                {
                    "request": request,
                    "assessment": assessment_data,
                    "product_key": cached["product_key"],
                    "cache_age": cache_age,
                },
            )

        # Step 2: Data Collection (run in parallel where possible)
        logger.info(f"Collecting data for {entity.product_name}")

        # Collect CVE data
        cve_data = await nvd_client.search_cves(
            entity.product_name,
            entity.vendor_name,
        )

        # Check CISA KEV
        kev_data = await kev_client.check_product_in_kev(
            entity.product_name,
            entity.vendor_name,
        )

        # Scrape security pages
        security_pages = {}
        terms_privacy = {}
        if entity.official_website:
            security_pages = await scraper.scrape_security_pages(entity.official_website)
            terms_privacy = await scraper.check_terms_and_privacy(entity.official_website)

        # Step 3: AI Synthesis
        logger.info(f"Synthesizing assessment for {entity.product_name}")
        assessment = await synthesizer.synthesize_assessment(
            product_name=entity.product_name,
            vendor_name=entity.vendor_name,
            official_website=entity.official_website,
            category=entity.category,
            description=entity.description,
            cve_data=cve_data,
            kev_data=kev_data,
            security_pages=security_pages,
            terms_privacy=terms_privacy,
        )

        # Add timestamp
        assessment.metadata.assessed_at = datetime.utcnow().isoformat()
        assessment.metadata.cache_hit = False

        # Convert to dict for storage and display
        assessment_dict = assessment.model_dump()

        # Collect all sources for storage
        sources = []
        for citation in assessment.citations.values():
            sources.append({
                "url": citation.url,
                "type": citation.type,
                "title": citation.title,
            })

        # Step 4: Cache the result
        await db.save_assessment(
            product_name=entity.product_name,
            vendor_name=entity.vendor_name,
            category=entity.category,
            trust_score=assessment.trust_score.score,
            assessment=assessment_dict,
            sources=sources,
        )

        # Step 5: Return assessment
        product_key = db._normalize_product_key(entity.product_name)

        return templates.TemplateResponse(
            "assessment.html",
            {
                "request": request,
                "assessment": assessment_dict,
                "product_key": product_key,
                "cache_age": None,
            },
        )

    except Exception as e:
        logger.error(f"Assessment failed: {str(e)}", exc_info=True)
        return templates.TemplateResponse(
            "components/error.html",
            {
                "request": request,
                "error": f"Assessment failed: {str(e)}",
            },
        )


@app.get("/assessment/{product_key}", response_class=HTMLResponse)
async def view_assessment(request: Request, product_key: str):
    """View cached assessment."""
    cached = await db.get_assessment(product_key)

    if not cached:
        raise HTTPException(status_code=404, detail="Assessment not found")

    assessment_data = cached["assessment"]
    assessment_data["metadata"]["cache_hit"] = True
    cache_age = calculate_cache_age(cached["timestamp"])

    return templates.TemplateResponse(
        "assessment.html",
        {
            "request": request,
            "assessment": assessment_data,
            "product_key": cached["product_key"],
            "cache_age": cache_age,
        },
    )


@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    """View recent assessments."""
    recent = await db.get_recent_assessments(limit=20)

    return templates.TemplateResponse(
        "history.html",
        {
            "request": request,
            "assessments": recent,
        },
    )


@app.post("/compare")
async def compare_products(request: Request, products: str = Form(...)):
    """Compare multiple products."""
    # Parse comma-separated product names
    product_list = [p.strip() for p in products.split(",")]

    if len(product_list) < 2:
        return templates.TemplateResponse(
            "components/error.html",
            {
                "request": request,
                "error": "Please provide at least 2 products to compare, separated by commas.",
            },
        )

    if len(product_list) > 4:
        return templates.TemplateResponse(
            "components/error.html",
            {
                "request": request,
                "error": "Maximum 4 products can be compared at once.",
            },
        )

    # Get or create assessments for each product
    assessments = []
    for product in product_list:
        # Check cache
        cached = await db.get_assessment(product)
        if cached:
            assessments.append(cached["assessment"])
        else:
            # Would need to create new assessment - for now, skip
            logger.warning(f"No cached assessment for {product}")

    return templates.TemplateResponse(
        "compare.html",
        {
            "request": request,
            "assessments": assessments,
        },
    )


@app.get("/api/cache/stats")
async def cache_stats():
    """Get cache statistics (JSON API)."""
    stats = await db.get_cache_stats()
    return JSONResponse(stats)


@app.delete("/api/cache")
async def clear_cache():
    """Clear cache (admin endpoint)."""
    await db.clear_cache()
    return JSONResponse({"status": "success", "message": "Cache cleared"})


@app.get("/api/assessment/{product_key}")
async def get_assessment_json(product_key: str):
    """Get assessment as JSON."""
    cached = await db.get_assessment(product_key)

    if not cached:
        raise HTTPException(status_code=404, detail="Assessment not found")

    return JSONResponse(cached["assessment"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )
