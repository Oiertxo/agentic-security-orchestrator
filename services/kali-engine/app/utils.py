import ipaddress
import os
import re
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

ALLOWED_NMAP_FLAGS = {"-sS", "-sV"}
ALLOWED_TOOLS = {"nmap", "dig"}
LAB_NETWORK = ipaddress.IPv4Network("10.255.255.0/24")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Safety caps
MAX_RESULTS_PER_PAGE = 200
MAX_TOTAL_RESULTS = 400
HTTP_TIMEOUT = 20

MAX_RETRIES = 5
BACKOFF_BASE = 1.5
BACKOFF_MAX = 30.0
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}


class ReconRequest(BaseModel):
    next_tool: str = Field(..., description="nmap | dig")
    target: str = Field(..., description="Lab IP")
    options: list[str] = Field(default=[])


class CveLookupRequest(BaseModel):
    # Structured fingerprint fields (from recon port_map)
    name: str = Field(..., min_length=1, max_length=100, description="e.g., activemq")
    product: str = Field(..., min_length=1, max_length=100, description="e.g., OpenSSH")
    version: Optional[str] = Field(
        default=None, max_length=200, description="e.g., 8.9p1 Ubuntu 3ubuntu0.13"
    )
    service: Optional[str] = Field(default=None, max_length=50, description="e.g., ssh")
    vendor: Optional[str] = Field(
        default=None, max_length=100, description="e.g., Canonical"
    )
    ostype: Optional[str] = Field(
        default=None, max_length=50, description="e.g., Linux"
    )
    extrainfo: Optional[str] = Field(
        default=None, max_length=200, description="e.g., Ubuntu Linux; protocol 2.0"
    )
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    # NVD query tuning
    resultsPerPage: int = Field(default=50, ge=1, le=MAX_RESULTS_PER_PAGE)
    maxResults: int = Field(default=200, ge=1, le=MAX_TOTAL_RESULTS)


class SearchsploitRequest(BaseModel):
    cve: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class ExploitRequest(BaseModel):
    command: str


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
            x = 1


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
    """

    parts = []
    if req.product:
        parts.append(req.product)

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
    metrics = cve.get("metrics", {})

    def first_metric(metric_key: str):
        arr = metrics.get(metric_key)
        return arr[0] if isinstance(arr, list) and arr else None

    def base_score(block):
        return block.get("cvssData", {}).get("baseScore") if block else None

    cvss_v31 = first_metric("cvssMetricV31")
    cvss_v30 = first_metric("cvssMetricV30")
    cvss_v2 = first_metric("cvssMetricV2")

    # Get configs
    configurations = []
    raw_configs = cve.get("configurations")
    nodes = []
    if isinstance(raw_configs, dict):
        nodes = raw_configs.get("nodes", [])
    elif isinstance(raw_configs, list):
        for entry in raw_configs:
            if isinstance(entry, dict):
                nodes.extend(entry.get("nodes", []))

    for node in nodes:
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable"):
                continue

            configurations.append(
                {
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": match.get("versionEndIncluding"),
                    "versionEndExcluding": match.get("versionEndExcluding"),
                }
            )

    return {
        "cve_id": cve_id,
        "cvss_v31_base": base_score(cvss_v31),
        "cvss_v30_base": base_score(cvss_v30),
        "cvss_v2_base": base_score(cvss_v2),
        "configurations": configurations,
    }


class FileUpdateRequest(BaseModel):
    path: str
    content_b64: str


def build_msf_module_path(kali_path: str) -> str:
    """
    Copy exploit to ~/.msf4/modules/<filename>.rb
    Example:
      /opt/exploitdb/.../9950.rb → ~/.msf4/modules/exploitdb/9950.rb
    """
    base_dir = os.path.expanduser("~/.msf4/modules/exploitdb")
    filename = os.path.basename(kali_path)
    return os.path.join(base_dir, filename)
