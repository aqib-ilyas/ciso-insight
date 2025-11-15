# CISO Insight

**AI-powered security assessment for CISOs**

Turn any application name or URL into a CISO-ready trust brief with sources in minutes.

Built for the WithSecure Junction 2025 hackathon challenge.

---

## Overview

CISO Insight helps security teams make faster, evidence-based decisions by automatically collecting and synthesizing security posture data from multiple sources:

- **CVE/Vulnerability Data**: Real-time data from NVD and CISA KEV catalog
- **Vendor Security Pages**: Bug bounty programs, PSIRT pages, security advisories
- **Compliance & Certifications**: SOC2, ISO 27001, GDPR, HIPAA attestations
- **Independent Sources**: Security researcher reports, incident data

Every assessment includes:
- **Trust Score (0-100)**: Transparent calculation showing exactly how the score is derived
- **Evidence Quality Ratings**: All sources tagged as "vendor-stated" or "independent"
- **CVE Analysis**: Severity breakdown, patch cadence, CISA KEV status
- **Full Citations**: Every claim backed by a numbered citation with URL

---

## Quick Start

### Prerequisites

- Python 3.9+
- OpenAI API key (GPT-4 or GPT-4o)
- Optional: NVD API key (for higher rate limits)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ciso-insight.git
cd ciso-insight
```

2. Create a virtual environment:
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API keys
# REQUIRED: OPENAI_API_KEY
# OPTIONAL: NVD_API_KEY
```

5. Run the application:
```bash
# Using the startup script
bash run.sh

# Or directly with Python
python -m app.main

# Or with uvicorn
uvicorn app.main:app --reload
```

6. Open your browser:
```
http://localhost:8000
```

---

## Usage Examples

### Simple Product Name
```
Input: "Slack"
→ Resolves to Slack by Salesforce
→ Assesses communication platform security
```

### URL Input
```
Input: "zoom.us"
→ Resolves to Zoom Video Communications
→ Collects security data from zoom.us/trust
```

### Non-Latin Characters
```
Input: "微信" (WeChat)
→ Handles Chinese characters correctly
→ Resolves to WeChat by Tencent
```

### Comparison
```
Input: "1Password, LastPass, Dashlane"
→ Assesses all three password managers
→ Side-by-side security comparison
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CISO Insight Web UI                     │
│              (FastAPI + Jinja2 + HTMX + Tailwind)            │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   Entity    │  │    Data     │  │     AI      │
    │  Resolver   │  │ Collectors  │  │ Synthesizer │
    │  (OpenAI)   │  │             │  │  (OpenAI)   │
    └─────────────┘  └─────────────┘  └─────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │  NVD CVE    │  │  CISA KEV   │  │   Web       │
    │   API       │  │  Catalog    │  │  Scraper    │
    └─────────────┘  └─────────────┘  └─────────────┘
                              │
                              ▼
                     ┌─────────────┐
                     │   SQLite    │
                     │   Cache     │
                     │  (24h TTL)  │
                     └─────────────┘
```

### Components

**1. Entity Resolution (20% of judging criteria)**
- Uses OpenAI GPT-4 to normalize product names
- Handles ambiguous inputs, URLs, non-Latin characters
- Extracts: product name, vendor, official website, category

**2. Data Collectors**
- **NVD Client**: Fetches CVE data from NIST National Vulnerability Database
- **CISA KEV Client**: Checks Known Exploited Vulnerabilities catalog
- **Web Scraper**: Collects security pages, compliance docs, terms/privacy

**3. AI Synthesis (36% of judging criteria: 12% synthesis + 24% citations)**
- Comprehensive system prompt optimized for security analysis
- Generates structured JSON with full citations
- Tags all sources as vendor-stated vs independent
- Transparent trust score calculation

**4. Caching Layer**
- SQLite database with 24-hour TTL
- Reproducible results for same input
- Enables fast history/comparison features

---

## Data Sources Priority

### Priority 1: Official Security Sources
- Vendor security/PSIRT pages
- Bug bounty programs (HackerOne, Bugcrowd)
- Security contact/disclosure policy

### Priority 2: Compliance & Certifications
- SOC 2 Type II reports
- ISO 27001 attestations
- Terms of Service / Privacy Policy
- Data Processing Agreements

### Priority 3: CVE & Vulnerability Data
- NIST NVD API: CVE search and statistics
- CISA KEV Catalog: Known exploited vulnerabilities
- CVE severity trends and patch cadence analysis

### Priority 4: Independent Sources
- CERT advisories
- Security researcher reports
- Known breach/incident reports

---

## Citation Methodology

**Every claim requires a citation:**
- Inline citations use [1][2] format
- Full citation list at bottom of assessment
- Each citation includes:
  - URL (clickable, verified)
  - Type: "vendor-stated" or "independent"
  - Title/description

**Source Tagging:**
- **Vendor-Stated**: From company's own website/docs
- **Independent**: From CVE databases, security researchers, government sources

**When data is missing:**
- Explicitly state "Insufficient public evidence"
- NO guessing or hallucinations
- Adjust confidence level accordingly

---

## Trust Score Calculation

**Base Score: 50/100**

**Adjustments:**
- **CVE Impact**: -20 to +10 based on severity/count/trend
- **Certifications**: +5 to +20 for SOC2, ISO27001, etc.
- **Breaches**: -10 to -30 based on severity/recency
- **Vendor Reputation**: -10 to +15 based on company maturity, incidents
- **Patch Cadence**: +5 for fast (<30 days), -5 for slow (>90 days)
- **CISA KEV**: -15 if vulnerabilities in KEV catalog

**Confidence Level:**
- **High**: Multiple independent sources + vendor data + CVE data
- **Medium**: Partial data, mostly vendor-stated or limited CVEs
- **Low**: Scarce public evidence, high uncertainty

**Data Completeness:**
- 0-100% score showing how much required data was found
- Affects confidence level

---

## API Endpoints

### Web UI
- `GET /` - Home page with search
- `POST /assess` - Process assessment (form: input=string)
- `GET /assessment/{product_key}` - View cached assessment
- `GET /history` - Recent assessments list
- `POST /compare` - Compare products (form: products=csv)

### JSON API
- `GET /api/assessment/{product_key}` - Assessment as JSON
- `GET /api/cache/stats` - Cache statistics
- `DELETE /api/cache` - Clear cache (admin)

---

## Configuration

Environment variables (`.env`):

```bash
# Required
OPENAI_API_KEY=sk-your-key-here

# Optional
NVD_API_KEY=optional              # Higher rate limits for NVD API
CACHE_TTL_HOURS=24                # Cache time-to-live
HOST=0.0.0.0                      # Server host
PORT=8000                         # Server port
LOG_LEVEL=INFO                    # Logging level
```

---

## Project Structure

```
ciso-insight/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app + routes
│   ├── models.py               # Pydantic models
│   ├── config.py               # Settings
│   ├── database.py             # SQLite operations
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── nvd.py              # NVD CVE API client
│   │   ├── cisa_kev.py         # CISA KEV catalog
│   │   └── scraper.py          # Web scraping
│   └── ai/
│       ├── __init__.py
│       ├── resolver.py         # Entity resolution
│       └── synthesizer.py      # Security synthesis
├── templates/
│   ├── base.html               # Base template
│   ├── index.html              # Home page
│   ├── assessment.html         # Assessment results
│   ├── history.html            # Assessment history
│   ├── compare.html            # Product comparison
│   └── components/
│       ├── loading.html
│       ├── error.html
│       ├── trust_score.html
│       ├── cve_section.html
│       └── citations.html
├── static/
│   ├── logo.svg
│   └── custom.css
├── requirements.txt
├── .env.example
├── README.md
└── run.sh
```

---

## Testing

Test with these products from the hackathon CSV:

**High Trust (75-95):**
- Slack
- 1Password
- Zoom

**Medium Trust (50-75):**
- TeamViewer
- FileZilla

**Low Trust / Insufficient Data:**
- Obscure freeware
- Random Chinese software

**CVE Heavy (but trusted):**
- 7-Zip
- WinRAR

**Comparison Test:**
```
1Password vs LastPass vs Dashlane
```

---

## Limitations & Future Improvements

### Current Limitations
1. **Data Coverage**: Limited to public sources; no access to internal security audits
2. **Real-time Data**: CVE data may be delayed by hours/days
3. **Language Support**: Best for English sources; limited non-Latin script support
4. **Rate Limits**: NVD API limited to 5 req/sec without API key
5. **Web Scraping**: Some security pages may be behind authentication

### Future Improvements
1. **Enhanced Data Sources**:
   - Integration with security rating services (BitSight, SecurityScorecard)
   - GitHub security advisories
   - Dark web monitoring for leaked credentials

2. **Advanced Analysis**:
   - ML-based anomaly detection in CVE patterns
   - Predictive scoring based on vendor behavior
   - Supply chain risk analysis

3. **Collaboration Features**:
   - Team sharing and annotations
   - Custom assessment templates
   - Vendor questionnaire automation

4. **Export & Integration**:
   - PDF report generation
   - Slack/Teams notifications
   - SIEM/GRC platform integration

5. **Continuous Monitoring**:
   - Webhook alerts for new CVEs
   - Automated re-assessment scheduling
   - Drift detection from baseline

---

## Tech Stack

- **Backend**: FastAPI (Python 3.9+)
- **Templates**: Jinja2
- **Frontend**: HTMX + TailwindCSS (CDN, no build step)
- **AI**: OpenAI GPT-4/GPT-4o
- **Database**: SQLite with aiosqlite
- **HTTP**: httpx (async)
- **Scraping**: BeautifulSoup4 + lxml
- **Config**: python-dotenv

---

## Team & License

Built for WithSecure Junction 2025 hackathon.

**Contributors:**
- [Your Name/Team Name]

**License:**
MIT License - see LICENSE file for details

---

## Support

For issues, questions, or feature requests:
- GitHub Issues: [your-repo-url]/issues
- Email: [your-email]

---

## Acknowledgments

- WithSecure for hosting Junction 2025
- NIST for the NVD API
- CISA for the KEV catalog
- OpenAI for GPT-4 API access
- The security research community

---

**CISO Insight** - Security posture in minutes.
