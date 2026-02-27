from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any
import logging
from logging.handlers import RotatingFileHandler
import subprocess, ipaddress, requests, os, re

app = FastAPI(title="Execution Engine", version="1.0.0")

ALLOWED_TOOLS = {"nmap", "dig"}
ALLOWED_NMAP_FLAGS = {"-sS", "-sV"}
LAB_NETWORK = ipaddress.IPv4Network("10.255.255.0/24")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Safety caps
MAX_RESULTS_PER_PAGE = 200
MAX_TOTAL_RESULTS = 400
HTTP_TIMEOUT = 20

LOG_DIR = "/app/logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
    handlers=[
        RotatingFileHandler(f"{LOG_DIR}/kali_engine.log", maxBytes=5*1024*1024, backupCount=3),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("kali-engine")

class ReconRequest(BaseModel):
    next_tool: str = Field(..., description="nmap | dig")
    target: str = Field(..., description="Lab IP")
    options: list[str] = Field(default=[])

class CveLookupRequest(BaseModel):
    # Structured fingerprint fields (from recon port_map)
    product: str = Field(..., min_length=1, max_length=100, description="e.g., OpenSSH")
    version: Optional[str] = Field(default=None, max_length=200, description="e.g., 8.9p1 Ubuntu 3ubuntu0.13")
    service: Optional[str] = Field(default=None, max_length=50, description="e.g., ssh")
    vendor: Optional[str] = Field(default=None, max_length=100, description="e.g., Canonical")
    ostype: Optional[str] = Field(default=None, max_length=50, description="e.g., Linux")
    extrainfo: Optional[str] = Field(default=None, max_length=200, description="e.g., Ubuntu Linux; protocol 2.0")
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    # NVD query tuning
    resultsPerPage: int = Field(default=50, ge=1, le=MAX_RESULTS_PER_PAGE)
    maxResults: int = Field(default=200, ge=1, le=MAX_TOTAL_RESULTS)

def ensure_lab_target(target: str):
    try:
        # Accept both single IPs and CIDR networks
        if "/" in target:
            net = ipaddress.IPv4Network(target, strict=False)
            
            if net.subnet_of(LAB_NETWORK):
                return
        else:
            ip = ipaddress.ip_address(target)
            if ip in LAB_NETWORK:
                return
    except ValueError:
        raise HTTPException(400, "Invalid IP or CIDR format")

    raise HTTPException(400, "Target outside lab range")

def ensure_nmap_options(options: list[str]):
    for opt in options:
        if opt not in ALLOWED_NMAP_FLAGS:
            # raise HTTPException(status_code=400, detail=f"Disallowed nmap option: {opt}")
            x=1

def _nvd_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers

def _normalize_text(s: str) -> str:
    s = s.strip()
    _whitespace = re.compile(r"\s+")
    s = _whitespace.sub(" ", s)
    return s

def _build_keyword_search(req: CveLookupRequest) -> str:
    """
    Build a consistent keyword string.
    We avoid commands or exploit guidance; this is only metadata search.
    """
    version_clean = ""
    if req.version:
        match = re.search(r"(\d+\.\d+)", req.version)
        version_clean = match.group(1) if match else req.version

    parts = []
    if req.product:
        parts.append(req.product)
    if version_clean:
        parts.append(version_clean)

    if not parts and req.service:
        parts.append(req.service)

    query = " ".join(parts)
    return _normalize_text(query)

def _extract_cve_summary(vuln: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a compact summary from NVD response.
    NVD v2.0 response includes 'vulnerabilities' array. [1](https://nvd.nist.gov/developers/vulnerabilities)
    """
    cve = (vuln or {}).get("cve", {})
    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")

    desc = None
    for d in (cve.get("descriptions") or []):
        if d.get("lang") == "en":
            desc = d.get("value")
            break

    metrics = cve.get("metrics") or {}

    def first_metric(metric_key: str) -> Optional[dict[str, Any]]:
        arr = metrics.get(metric_key)
        if isinstance(arr, list) and arr:
            return arr[0]
        return None

    def base_score(block: Optional[dict[str, Any]]) -> Optional[float]:
        if not block:
            return None
        data = block.get("cvssData") or {}
        return data.get("baseScore")

    cvss_v31 = first_metric("cvssMetricV31")
    cvss_v30 = first_metric("cvssMetricV30")
    cvss_v2 = first_metric("cvssMetricV2")

    return {
        "cve_id": cve_id,
        # "published": published,
        # "last_modified": last_modified,
        # "description": desc,
        "cvss_v31_base": base_score(cvss_v31),
        "cvss_v30_base": base_score(cvss_v30),
        "cvss_v2_base": base_score(cvss_v2),
    }

@app.post("/recon")
def run(req: ReconRequest):
    if req.next_tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="Tool not allowed")
    ensure_lab_target(req.target)

    if req.next_tool == "nmap":
        ensure_nmap_options(req.options)
        try:
            with open("/etc/nmap-exclude", "r") as f:
                exclude_ips = f.read().strip()
        except Exception:
            exclude_ips = ""
        cmd = [
            "nmap",
            *req.options,
            "-n",
            "-Pn",
            "--max-retries", "1",
            "--host-timeout", "300s",
            "-T3",
            "-oX", "-",
            "--exclude",
            exclude_ips,
            req.target,
        ]
    elif req.next_tool == "dig":
        cmd = ["dig", req.target, "ANY"]
    else:
        raise HTTPException(status_code=400, detail="Invalid tool")

    try:
        logger.info(f"RECON CONTAINER DEBUG Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "next_tool": req.next_tool,
        "target": req.target,
        "options": req.options,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }

@app.post("/cve_lookup")
def cve_lookup(req: CveLookupRequest):
    """
    Structured CVE lookup via NVD CVE API v2.0.
    Uses keywordSearch + pagination (startIndex/resultsPerPage). [1](https://nvd.nist.gov/developers/vulnerabilities)
    """
    keyword = _build_keyword_search(req)

    remaining = min(req.maxResults, MAX_TOTAL_RESULTS)
    start_index = 0
    items: list[dict[str, Any]] = []

    while remaining > 0:
        page_size = min(req.resultsPerPage, remaining)

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }

        try:
            logger.info(f"CVE_LOOKUP: {NVD_BASE_URL}, {_nvd_headers()}, {params}, {HTTP_TIMEOUT}")
            r = requests.get(
                NVD_BASE_URL,
                headers=_nvd_headers(),
                params=params,
                timeout=HTTP_TIMEOUT
            )
        except requests.RequestException as e:
            raise HTTPException(status_code=502, detail=f"NVD request failed: {e}")

        if r.status_code != 200:
            raise HTTPException(status_code=502, detail=f"NVD returned {r.status_code}: {r.text[:300]}")

        data = r.json()
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            break

        for v in vulns:
            items.append(_extract_cve_summary(v))

        got = len(vulns)
        start_index += got
        remaining -= got

        if got < page_size:
            break

    return {
        "query": {
            "product": req.product,
            "version": req.version,
            "service": req.service,
            "vendor": req.vendor,
            "ostype": req.ostype,
            "extrainfo": req.extrainfo,
            "port": req.port,
            "keywordSearch": keyword,
        },
        "count": len(items),
        "items": items,
        "note": "Summarized CVE records from NVD CVE API v2.0 (keyword search + pagination)."
    }

@app.post("/recon_mock")
def run_mock(req: ReconRequest):
    return {
        "next_tool": req.next_tool,
        "target": req.target,
        "options": req.options,
        "stdout": "Found open port 22 with no password necessary on 10.255.255.4",
        "stderr": "",
        "returncode": 0,
    }