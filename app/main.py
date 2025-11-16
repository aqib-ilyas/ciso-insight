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
from .collectors.virustotal import VirusTotalClient
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
virustotal_client = VirusTotalClient()
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
async def assess_product(request: Request, input: str = Form(...), version: str = Form(None)):
    """Process security assessment."""
    logger.info(f"Assessment request for: {input}, version: {version or 'auto-detect'}")

    try:
        # Step 1: Entity Resolution
        entity = await resolver.resolve_entity(input, user_version=version)

        if entity.product_name == "UNKNOWN":
            return templates.TemplateResponse(
                "components/error.html",
                {
                    "request": request,
                    "error": "Could not identify the product. Please provide a more specific product name or URL.",
                },
            )

        logger.info(f"✓ Resolved entity: {entity.product_name} (Vendor: {entity.vendor_name}, Version: {entity.version})")

        # Step 1.5: Verify domain if official website exists
        if entity.official_website:
            domain_valid = await scraper.verify_domain(entity.official_website)
            if not domain_valid:
                return templates.TemplateResponse(
                    "components/error.html",
                    {
                        "request": request,
                        "error": f"The domain {entity.official_website} could not be verified or is not accessible. Please check the URL and try again.",
                    },
                )

        # Check cache first
        cached = await db.get_assessment(entity.product_name, entity.version)
        if cached:
            logger.info(f"Returning cached assessment for {entity.product_name}")
            assessment_data = cached["assessment"]
            assessment_data["metadata"]["cache_hit"] = True
            cache_age = calculate_cache_age(cached["timestamp"])

            return templates.TemplateResponse(
                "components/assessment_inline.html",
                {
                    "request": request,
                    "assessment": assessment_data,
                    "product_key": cached["product_key"],
                    "cache_age": cache_age,
                },
            )

        # Step 2: Data Collection (run in parallel where possible)
        logger.info(f"Collecting data for {entity.product_name}")

        # Collect CVE data from NVD and CISA KEV in parallel
        import asyncio
        nvd_task = nvd_client.search_cves(
            entity.product_name,
            entity.vendor_name,
            entity.version,
        )
        kev_task = kev_client.check_product_in_kev(
            entity.product_name,
            entity.vendor_name,
        )

        cve_data, kev_data = await asyncio.gather(nvd_task, kev_task)

        # Filter KEV vulnerabilities to only include those present in final NVD results
        # This ensures version-specific filtering is respected
        if kev_data.get("in_kev") and kev_data.get("kev_vulnerabilities"):
            # Get ALL CVE IDs that passed version filtering (not just notable top 5)
            nvd_cve_ids = set(cve_data.get("all_cve_ids", []))

            # If we have NVD CVEs, filter KEV to only those that appear in NVD results
            if nvd_cve_ids:
                original_kev_count = len(kev_data["kev_vulnerabilities"])
                filtered_kev_vulns = [
                    kev_vuln for kev_vuln in kev_data["kev_vulnerabilities"]
                    if kev_vuln.get("cve_id") in nvd_cve_ids
                ]

                kev_data["kev_vulnerabilities"] = filtered_kev_vulns
                kev_data["kev_count"] = len(filtered_kev_vulns)
                kev_data["in_kev"] = len(filtered_kev_vulns) > 0

                if original_kev_count > len(filtered_kev_vulns):
                    logger.info(
                        f"KEV filtering: {original_kev_count} KEV CVEs → {len(filtered_kev_vulns)} "
                        f"after version filtering (removed {original_kev_count - len(filtered_kev_vulns)} "
                        f"CVEs that don't affect version {entity.version})"
                    )
            else:
                # No NVD CVEs found, but we have KEV - need to verify each KEV CVE
                logger.warning(
                    f"KEV has {kev_data['kev_count']} CVEs but NVD search found 0. "
                    f"Verifying KEV CVEs against version {entity.version}"
                )

                verified_kev_vulns = []
                kev_cve_ids = [v.get("cve_id") for v in kev_data.get("kev_vulnerabilities", [])]

                for cve_id in kev_cve_ids[:5]:  # Limit to avoid rate limits
                    try:
                        specific_cve = await nvd_client.search_cve_by_id(cve_id, entity.version)
                        if specific_cve and specific_cve.get("total_cves", 0) > 0:
                            # This KEV CVE affects the version
                            kev_vuln = next((v for v in kev_data["kev_vulnerabilities"] if v.get("cve_id") == cve_id), None)
                            if kev_vuln:
                                verified_kev_vulns.append(kev_vuln)

                            # Add to CVE data
                            if cve_data.get("total_cves", 0) == 0:
                                cve_data = specific_cve
                            else:
                                cve_data["total_cves"] += specific_cve.get("total_cves", 0)
                                cve_data["critical_count"] += specific_cve.get("critical_count", 0)
                                cve_data["high_count"] += specific_cve.get("high_count", 0)
                                cve_data["notable_cves"].extend(specific_cve.get("notable_cves", []))
                    except Exception as e:
                        logger.error(f"Failed to lookup CVE {cve_id}: {e}")

                # Update KEV data with only verified vulnerabilities
                kev_data["kev_vulnerabilities"] = verified_kev_vulns
                kev_data["kev_count"] = len(verified_kev_vulns)
                kev_data["in_kev"] = len(verified_kev_vulns) > 0

        logger.info(
            f"Final results for version {entity.version}: "
            f"{cve_data['total_cves']} total CVEs, "
            f"{kev_data.get('kev_count', 0)} KEV vulnerabilities"
        )

        # Scrape security pages and analyze domain reputation in parallel
        security_pages = {}
        terms_privacy = {}
        virustotal_data = {}

        if entity.official_website:
            # Run these in parallel for performance
            security_task = scraper.scrape_security_pages(entity.official_website)
            terms_task = scraper.check_terms_and_privacy(entity.official_website)
            vt_task = virustotal_client.analyze_domain(entity.official_website)

            security_pages, terms_privacy, virustotal_data = await asyncio.gather(
                security_task, terms_task, vt_task
            )

            logger.info(
                f"Domain reputation: {virustotal_data.get('safety_score', 'unknown')}, "
                f"VT reputation score: {virustotal_data.get('reputation_score', 0)}"
            )

        # Step 3: AI Synthesis
        logger.info(
            f"Synthesizing assessment for {entity.product_name} "
            f"(version: {entity.version}, SHA1: {entity.sha1 or 'N/A'})"
        )
        assessment = await synthesizer.synthesize_assessment(
            product_name=entity.product_name,
            vendor_name=entity.vendor_name,
            official_website=entity.official_website,
            category=entity.category,
            description=entity.description,
            version=entity.version,
            sha1=entity.sha1,
            cve_data=cve_data,
            kev_data=kev_data,
            security_pages=security_pages,
            terms_privacy=terms_privacy,
            virustotal_data=virustotal_data,
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
            version=entity.version,
            trust_score=assessment.trust_score.score,
            assessment=assessment_dict,
            sources=sources,
        )

        # Step 5: Return assessment (inline for HTMX)
        product_key = db._normalize_product_key(entity.product_name, entity.version)

        return templates.TemplateResponse(
            "components/assessment_inline.html",
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
    cached = await db.get_assessment_by_key(product_key)

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


@app.get("/compare/{product1}/{product2}", response_class=HTMLResponse)
async def compare_two_products(request: Request, product1: str, product2: str):
    """Compare two products side by side."""
    logger.info(f"Comparing {product1} vs {product2}")

    try:
        # Get or generate assessments for both products
        assessments = []

        for product_name in [product1, product2]:
            # Resolve entity to get version
            entity = await resolver.resolve_entity(product_name)

            if entity.product_name == "UNKNOWN":
                raise HTTPException(
                    status_code=404,
                    detail=f"Could not identify product: {product_name}"
                )

            # Check cache first
            cached = await db.get_assessment(entity.product_name, entity.version)

            if cached:
                logger.info(f"Using cached assessment for {product_name}")
                assessment_data = cached["assessment"]
                assessment_data["metadata"]["cache_hit"] = True
                assessments.append(assessment_data)
            else:
                # Need to generate new assessment
                logger.info(f"Generating new assessment for {product_name}")

                # Collect data (abbreviated for performance)
                import asyncio
                nvd_task = nvd_client.search_cves(entity.product_name, entity.vendor_name, entity.version)
                kev_task = kev_client.check_product_in_kev(entity.product_name, entity.vendor_name)
                cve_data, kev_data = await asyncio.gather(nvd_task, kev_task)

                # Filter KEV vulnerabilities to only include those present in final NVD results
                if kev_data.get("in_kev") and kev_data.get("kev_vulnerabilities"):
                    # Get ALL CVE IDs that passed version filtering (not just notable top 5)
                    nvd_cve_ids = set(cve_data.get("all_cve_ids", []))

                    if nvd_cve_ids:
                        original_kev_count = len(kev_data["kev_vulnerabilities"])
                        filtered_kev_vulns = [
                            kev_vuln for kev_vuln in kev_data["kev_vulnerabilities"]
                            if kev_vuln.get("cve_id") in nvd_cve_ids
                        ]

                        kev_data["kev_vulnerabilities"] = filtered_kev_vulns
                        kev_data["kev_count"] = len(filtered_kev_vulns)
                        kev_data["in_kev"] = len(filtered_kev_vulns) > 0

                        if original_kev_count > len(filtered_kev_vulns):
                            logger.info(
                                f"KEV filtering: {original_kev_count} → {len(filtered_kev_vulns)} "
                                f"(version {entity.version})"
                            )
                    else:
                        # No NVD CVEs found, verify KEV CVEs
                        logger.warning(f"Verifying KEV CVEs against version {entity.version}")

                        verified_kev_vulns = []
                        kev_cve_ids = [v.get("cve_id") for v in kev_data.get("kev_vulnerabilities", [])]

                        for cve_id in kev_cve_ids[:5]:
                            try:
                                specific_cve = await nvd_client.search_cve_by_id(cve_id, entity.version)
                                if specific_cve and specific_cve.get("total_cves", 0) > 0:
                                    kev_vuln = next((v for v in kev_data["kev_vulnerabilities"] if v.get("cve_id") == cve_id), None)
                                    if kev_vuln:
                                        verified_kev_vulns.append(kev_vuln)

                                    if cve_data.get("total_cves", 0) == 0:
                                        cve_data = specific_cve
                                    else:
                                        cve_data["total_cves"] += specific_cve.get("total_cves", 0)
                                        cve_data["critical_count"] += specific_cve.get("critical_count", 0)
                                        cve_data["high_count"] += specific_cve.get("high_count", 0)
                                        cve_data["notable_cves"].extend(specific_cve.get("notable_cves", []))
                            except Exception as e:
                                logger.error(f"Failed to lookup CVE {cve_id}: {e}")

                        kev_data["kev_vulnerabilities"] = verified_kev_vulns
                        kev_data["kev_count"] = len(verified_kev_vulns)
                        kev_data["in_kev"] = len(verified_kev_vulns) > 0

                security_pages = {}
                terms_privacy = {}
                virustotal_data = {}
                if entity.official_website:
                    security_task = scraper.scrape_security_pages(entity.official_website)
                    terms_task = scraper.check_terms_and_privacy(entity.official_website)
                    vt_task = virustotal_client.analyze_domain(entity.official_website)
                    security_pages, terms_privacy, virustotal_data = await asyncio.gather(
                        security_task, terms_task, vt_task
                    )

                # Synthesize assessment
                assessment = await synthesizer.synthesize_assessment(
                    product_name=entity.product_name,
                    vendor_name=entity.vendor_name,
                    official_website=entity.official_website,
                    category=entity.category,
                    description=entity.description,
                    version=entity.version,
                    sha1=entity.sha1,
                    cve_data=cve_data,
                    kev_data=kev_data,
                    security_pages=security_pages,
                    terms_privacy=terms_privacy,
                    virustotal_data=virustotal_data,
                )

                assessment.metadata.assessed_at = datetime.utcnow().isoformat()
                assessment.metadata.cache_hit = False
                assessment_dict = assessment.model_dump()

                # Cache it
                sources = []
                for citation in assessment.citations.values():
                    sources.append({
                        "url": citation.url,
                        "type": citation.type,
                        "title": citation.title,
                    })

                await db.save_assessment(
                    product_name=entity.product_name,
                    vendor_name=entity.vendor_name,
                    category=entity.category,
                    version=entity.version,
                    trust_score=assessment.trust_score.score,
                    assessment=assessment_dict,
                    sources=sources,
                )

                assessments.append(assessment_dict)

        return templates.TemplateResponse(
            "compare.html",
            {
                "request": request,
                "assessment1": assessments[0],
                "assessment2": assessments[1],
            },
        )

    except Exception as e:
        logger.error(f"Comparison failed: {str(e)}", exc_info=True)
        return templates.TemplateResponse(
            "components/error.html",
            {
                "request": request,
                "error": f"Comparison failed: {str(e)}",
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
        # Check cache (default to "latest" version)
        cached = await db.get_assessment(product, "latest")
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
    cached = await db.get_assessment_by_key(product_key)

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
