import ipaddress
import os
import re
import subprocess
from typing import Any, Dict, Optional, Tuple

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
    app_name: str = Field(
        ..., min_length=1, max_length=100, description="e.g., langflow"
    )
    app_version: Optional[str] = Field(
        default=None, max_length=200, description="e.g., 1.2.0"
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


def _extract_cve_summary(vuln: Dict[str, Any]) -> Dict[str, Any]:
    cve = (vuln or {}).get("cve", {})
    cve_id = cve.get("id")

    # Description for parser
    descriptions = cve.get("descriptions", [])
    full_desc = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"), ""
    )

    # Extract CVSS scores
    metrics = cve.get("metrics", {})

    def get_score(metric_key: str):
        arr = metrics.get(metric_key)
        return (
            arr[0].get("cvssData", {}).get("baseScore")
            if isinstance(arr, list) and arr
            else None
        )

    # Extract configurations from table
    configurations = []
    raw_configs = cve.get("configurations", [])

    all_nodes = []
    if isinstance(raw_configs, list):
        for cfg in raw_configs:
            all_nodes.extend(cfg.get("nodes", []))
    elif isinstance(raw_configs, dict):
        all_nodes = raw_configs.get("nodes", [])

    def walk_nodes(nodes):
        for node in nodes:
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue

                # Extract CPE version if no ranges (CouchDB 2.0.0 case)
                s_inc = match.get("versionStartIncluding")
                e_inc = match.get("versionEndIncluding")
                if not any(
                    [
                        s_inc,
                        match.get("versionStartExcluding"),
                        e_inc,
                        match.get("versionEndExcluding"),
                    ]
                ):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) > 5 and parts[5] not in ["*", "-"]:
                        s_inc = parts[5]
                        e_inc = parts[5]

                conf = {
                    "versionStartIncluding": s_inc,
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": e_inc,
                    "versionEndExcluding": match.get("versionEndExcluding"),
                }
                if (
                    any(v is not None for v in conf.values())
                    and conf not in configurations
                ):
                    configurations.append(conf)

            if "children" in node:
                walk_nodes(node.get("children", []))

    walk_nodes(all_nodes)

    # Enrichment: Extract from text and merge to maximize vulnerable range
    if full_desc:
        desc_based_configs = _parse_versions_from_description(full_desc)
        for dc in desc_based_configs:
            merged = False
            d_start = dc.get("versionStartIncluding")
            d_end_inc = dc.get("versionEndIncluding")
            d_end_exc = dc.get("versionEndExcluding")

            for ec in configurations:

                def get_maj(v):
                    return str(v).split(".")[0] if v and "." in str(v) else None

                e_ref = ec.get("versionStartIncluding") or ec.get("versionEndExcluding")
                d_ref = d_start or d_end_exc

                if get_maj(e_ref) == get_maj(d_ref) and get_maj(e_ref) is not None:
                    if d_start:
                        # If description has a start, and we already had one, keep the oldest (minimum)
                        if ec.get("versionStartIncluding"):
                            if safe_lesser_than(
                                _parse_version_tuple(d_start),
                                _parse_version_tuple(ec["versionStartIncluding"]),
                            ):
                                ec["versionStartIncluding"] = d_start
                        else:
                            ec["versionStartIncluding"] = d_start

                    # If description gives a range (Excluding), it's usually more accurate than a specific point from CPE.
                    if d_end_exc:
                        ec["versionEndExcluding"] = d_end_exc
                        # REMOVE restrictive point limit if the range is wider
                        ec["versionEndIncluding"] = None

                    if d_end_inc:
                        if ec.get("versionEndIncluding"):
                            if safe_greater_than(
                                _parse_version_tuple(d_end_inc),
                                _parse_version_tuple(ec["versionEndIncluding"]),
                            ):
                                ec["versionEndIncluding"] = d_end_inc
                        else:
                            ec["versionEndIncluding"] = d_end_inc

                    merged = True
                    break

            if not merged:
                configurations.append(dc)

    return {
        "cve_id": cve_id,
        "cvss_v31_base": get_score("cvssMetricV31"),
        "cvss_v30_base": get_score("cvssMetricV30"),
        "cvss_v2_base": get_score("cvssMetricV2"),
        "configurations": configurations,
    }


def _parse_version_tuple(v: str) -> Optional[Tuple[int, ...]]:
    if not v:
        return None
    clean_v = re.sub(r"[^0-9.]", "", v).strip(".")
    parts = clean_v.split(".")
    try:
        t = tuple(int(p) for p in parts if p.isdigit())
        return t if t else None
    except ValueError:
        return None


def _parse_versions_from_description(description: str) -> list[dict]:
    """
    Advanced extraction of version constraints from natural language descriptions.
    Covers: 'before X', 'prior to X', '2.x before Y', 'A through B', 'up to and including Z'.
    """
    configs = []
    desc_clean = description.lower()

    # --- PATTERN 1: Specific branches (e.g., "2.x before 2.1.1" or "1.x through 1.5.0") ---
    # Captures: branch (group 1), relation (before/through), limit (group 2)
    branch_matches = re.finditer(
        r"(\d+)\.(?:x|\*)\s+(before|prior to|earlier than|through|up to|to)\s+([\d\.]+)",
        desc_clean,
    )
    for m in branch_matches:
        major = m.group(1)
        rel = m.group(2)
        version_limit = m.group(3).strip(".")

        conf = {"versionStartIncluding": f"{major}.0.0"}
        if rel in ["before", "prior to", "earlier than"]:
            conf["versionEndExcluding"] = version_limit
        else:
            conf["versionEndIncluding"] = version_limit

        configs.append(conf)

    # --- PATTERN 2: Ranges (e.g., "0.8.0 through 0.11.0" or "from 1.2 to 1.5") ---
    range_matches = re.finditer(
        r"(?:from\s+)?([\d\.]+)\s+(?:through|to|up to)\s+([\d\.]+)", desc_clean
    )
    for m in range_matches:
        v_start = m.group(1).strip(".")
        v_end = m.group(2).strip(".")
        # Avoid single digit captures that aren't versions
        if v_start.count(".") >= 1 and v_end.count(".") >= 1:
            configs.append(
                {
                    "versionStartIncluding": v_start,
                    "versionEndIncluding": v_end,
                }
            )

    # --- PATTERN 3: Simple limits (e.g., "before 1.7.0", "up to and including 2.2") ---
    # Only if we haven't found branch-specific info to avoid double mapping
    if not configs:
        # Exclusive: "before 1.7.0"
        exc_match = re.search(
            r"(?:before|prior to|earlier than|up to \(excluding\))\s+([\d\.]+)",
            desc_clean,
        )
        if exc_match:
            configs.append(
                {
                    "versionEndExcluding": exc_match.group(1).strip("."),
                }
            )

        # Inclusive: "up to and including 1.5.0"
        inc_match = re.search(
            r"(?:up to and including|through|versions up to)\s+([\d\.]+)", desc_clean
        )
        if inc_match:
            configs.append(
                {
                    "versionEndIncluding": inc_match.group(1).strip("."),
                }
            )

    return configs


def safe_lesser_than(a, b):
    if a is None or b is None:
        return False
    return a < b


def safe_greater_than(a, b):
    if a is None or b is None:
        return False
    return a > b


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


def get_local_ip_for_target(target_ip: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "route", "get", target_ip],
            capture_output=True,
            text=True,
        )
        match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", result.stdout)

        if match:
            return match.group(1)

        return "127.0.0.1"

    except Exception:
        return "127.0.0.1"
