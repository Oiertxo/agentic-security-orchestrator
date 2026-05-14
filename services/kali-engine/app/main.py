import base64
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
from itertools import combinations
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

import requests
from executors.bind_shell import TriggerBindShellExecutor
from executors.bruteforce import execute as bruteforce_execute
from executors.framework_module import (
    framework_module_execute,
    framework_module_search_execute,
)
from executors.http_rce_single_request import HttpRceSingleRequestExecutor
from executors.reverse_shell import TriggerReverseShellExecutor
from fastapi import FastAPI, HTTPException

from utils import (
    ALLOWED_TOOLS,
    BACKOFF_BASE,
    BACKOFF_MAX,
    HTTP_TIMEOUT,
    MAX_RETRIES,
    MAX_TOTAL_RESULTS,
    NVD_BASE_URL,
    RETRY_STATUS_CODES,
    CveLookupRequest,
    ExploitRequest,
    FileUpdateRequest,
    ReconRequest,
    SearchsploitRequest,
    _extract_cve_summary,
    _nvd_headers,
    build_msf_module_path,
    ensure_lab_target,
    ensure_nmap_options,
)

app = FastAPI(title="Execution Engine", version="1.0.0")

LOG_DIR = "/app/logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        RotatingFileHandler(
            f"{LOG_DIR}/kali_engine.log", maxBytes=5 * 1024 * 1024, backupCount=3
        ),
        logging.StreamHandler(),
    ],
)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger("kali-engine")


@app.post("/recon")
def run(req: ReconRequest):
    if req.next_tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="Tool not allowed")
    ensure_lab_target(req.target)

    if req.next_tool == "nmap":
        ensure_nmap_options(req.options)
        if "-sS" in req.options:
            req.options.append("-p-")
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
            "--max-retries",
            "1",
            "--host-timeout",
            "300s",
            "-T4",
            "-oX",
            "-",
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

    This endpoint performs an adaptive multi-keyword search:
    - Generates keyword combinations from product and name
    - Executes searches incrementally
    - Selects keywords based on observed signal
    - Deduplicates CVEs
    - Version filtering is performed locally, not in NVD
    """

    logger.info(
        f"[CVE_LOOKUP] target={req.port} product={req.product} name={req.name} app_name={req.app_name}"
    )

    search_targets = []

    # App first
    if req.app_name:
        search_targets.append({"product": req.app_name, "name": req.name})

    # Service later
    if req.product:
        search_targets.append({"product": req.product, "name": req.name})

    all_items: dict[str, dict] = {}
    combined_signal = {}
    keywords_tested = []

    for target in search_targets:
        logger.info(f"[CVE_LOOKUP] Searching: {target}")

        result = nvd_multi_keyword_search(
            name=target["name"],
            product=target["product"],
            resultsPerPage=req.resultsPerPage,
            max_results=req.maxResults,
        )

        # Merge signals
        combined_signal.update(result.get("signal", {}))
        keywords_tested.extend(result.get("keywords_tested", []))

        # Merge CVEs
        for cve in result["items"]:
            if cve["cve_id"] not in all_items:
                cve["found_by"] = cve.get("found_by", []) + [target["product"]]
                all_items[cve["cve_id"]] = cve
            else:
                all_items[cve["cve_id"]]["found_by"].append(target["product"])

    return {
        "query": {
            "name": req.name,
            "product": req.product,
            "app_name": req.app_name,
            "version": req.version,
            "app_version": req.app_version,
            "service": req.service,
            "vendor": req.vendor,
            "ostype": req.ostype,
            "extrainfo": req.extrainfo,
            "port": req.port,
            "keywords_tested": keywords_tested,
            "signal": combined_signal,
        },
        "count": len(all_items),
        "items": list(all_items.values()),
        "note": (
            "Aggregated CVE results from application and infrastructure layers. "
            "Adaptive multi-keyword search without version constraints."
        ),
    }


def _nvd_keyword_search(resultsPerPage, keyword: str, max_results: int) -> dict:
    remaining = min(max_results, MAX_TOTAL_RESULTS)
    start_index = 0
    items: dict[str, dict] = {}

    while remaining > 0:
        page_size = min(resultsPerPage, remaining)

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }

        attempt = 0
        while True:
            try:
                r = requests.get(
                    NVD_BASE_URL,
                    headers=_nvd_headers(),
                    params=params,
                    timeout=HTTP_TIMEOUT,
                )
            except requests.RequestException as e:
                if attempt >= MAX_RETRIES:
                    raise HTTPException(
                        status_code=502,
                        detail=f"NVD request failed after retries: {e}",
                    )
                _backoff_sleep(attempt)
                attempt += 1
                continue

            if r.status_code == 200:
                break

            if r.status_code in RETRY_STATUS_CODES:
                if attempt >= MAX_RETRIES:
                    raise HTTPException(
                        status_code=502,
                        detail=f"NVD returned {r.status_code} after retries: {r.text[:300]}",
                    )
                _backoff_sleep(attempt)
                attempt += 1
                continue

            raise HTTPException(
                status_code=502,
                detail=f"NVD returned {r.status_code}: {r.text[:300]}",
            )

        data = r.json()
        logger.warning(f"[CVE_RESPONSE] Raw: {data}")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            cve = _extract_cve_summary(v)
            if (
                (cve.get("cvss_v31_base") and cve["cvss_v31_base"] >= 8.0)
                or (cve.get("cvss_v30_base") and cve["cvss_v30_base"] >= 8.0)
                or (cve.get("cvss_v2_base") and cve["cvss_v2_base"] >= 8.0)
            ):
                items.setdefault(cve["cve_id"], cve)

        got = len(vulns)
        start_index += got
        remaining -= got

        if got < page_size:
            break

    return {
        "keyword": keyword,
        "count": len(items),
        "items": list(items.values()),
    }


def _backoff_sleep(attempt: int) -> None:
    delay = min(BACKOFF_BASE * (2**attempt), BACKOFF_MAX)
    jitter = random.uniform(0, delay * 0.2)
    time.sleep(delay + jitter)


def keyword_combinations(text: str, max_len: int = 3) -> list[str]:
    tokens = [t.lower() for t in re.split(r"\W+", text) if t]

    seen = set()
    combos = []

    for size in range(1, min(len(tokens), max_len) + 1):
        for combo in combinations(tokens, size):
            k = " ".join(combo)
            if k not in seen:
                seen.add(k)
                combos.append(k)

    return combos


def nvd_multi_keyword_search(
    *,
    name: str | None,
    product: str,
    resultsPerPage: int,
    max_results: int,
    min_signal: int = 1,
) -> dict:
    keywords = []

    if name:
        keywords.append(name.lower())

    keywords.extend(keyword_combinations(product))

    all_items: dict[str, dict] = {}
    signal: dict[str, int] = {}
    executed: list[str] = []

    for keyword in keywords:
        result = _nvd_keyword_search(resultsPerPage, keyword, max_results)

        executed.append(keyword)
        signal[keyword] = result["count"]

        if result["count"] < min_signal:
            continue

        for cve in result["items"]:
            if cve["cve_id"] not in all_items:
                cve["found_by"] = [keyword]
                all_items[cve["cve_id"]] = cve
            else:
                all_items[cve["cve_id"]]["found_by"].append(keyword)

    return {
        "keywords_tested": executed,
        "signal": signal,
        "count": len(all_items),
        "items": list(all_items.values()),
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


@app.get("/read_exploit_file")
def read_exploit(path: str):
    safe_base = "/opt/exploitdb"
    absolute_path = os.path.abspath(path)

    if not absolute_path.startswith(safe_base):
        raise HTTPException(
            status_code=403, detail="Access denied: Path is outside exploitdb"
        )

    if not os.path.exists(absolute_path):
        raise HTTPException(status_code=404, detail="Exploit file not found")

    try:
        with open(absolute_path, "r", encoding="utf-8", errors="ignore") as f:
            return {"path": absolute_path, "content": f.read()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


@app.post("/search_exploit")
def search_exploit(request: SearchsploitRequest):
    """
    Searches on ExploitDB using CVEs or Product + version.
    """
    logger.info(f"SEARCHSPLOIT request: {request}")

    all_results = []

    if request.cve:
        cmd_cve = f"searchsploit --json --cve {request.cve}"
        logger.info(f"SEARCHSPLOIT command: {cmd_cve}")
        res_cve = subprocess.run(cmd_cve, shell=True, capture_output=True, text=True)
        if res_cve.returncode == 0:
            all_results.extend(json.loads(res_cve.stdout).get("RESULTS_EXPLOIT", []))

    if request.product:
        query = f"{request.product} {request.version or ''}".strip()
        cmd_txt = f"searchsploit --json {query}"
        logger.info(f"SEARCHSPLOIT command: {cmd_txt}")
        res_txt = subprocess.run(cmd_txt, shell=True, capture_output=True, text=True)
        if res_txt.returncode == 0:
            all_results.extend(json.loads(res_txt.stdout).get("RESULTS_EXPLOIT", []))

    unique_exploits = {exp["EDB-ID"]: exp for exp in all_results}.values()
    sorted_exploits = sorted(
        list(unique_exploits), key=lambda x: x.get("Verified") == "1", reverse=True
    )

    return {
        "query": {
            "cve": request.cve,
            "product": request.product,
            "version": request.version,
        },
        "count": len(sorted_exploits),
        "results": sorted_exploits,
        "status": "success",
    }


@app.post("/exploit")
def exploit(request: ExploitRequest):
    cmd = request.command
    if not cmd:
        return {"status": "TECHNICAL_ERROR", "details": "No command received"}

    logger.info(f"[MANUAL] Command: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    logger.info(f"[MANUAL] Result: {result}")

    ERROR_PATTERNS = [
        "request failed",
        "invalid url",
        "no scheme supplied",
        "connection refused",
        "connection error",
        "timeout",
        "traceback",
        "exception",
        "error:",
        "unknown command",
        "failed",
        "not found",
        "unable to",
        "could not",
        "no such file",
        "denied",
        "invalid",
        "bad",
        "usage:",
    ]

    SUCCESS_PATTERNS = [
        "uid=",
        "gid=",
        "root",
        "www-data",
    ]

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    combined = f"{stdout}\n{stderr}".lower()

    if any(err in combined for err in ERROR_PATTERNS):
        status = "FAILURE"
        details = stdout or stderr or "Exploit reported an error"

    elif any(ok in combined for ok in SUCCESS_PATTERNS):
        status = "SUCCESS"
        details = stdout

    elif result.returncode != 0:
        status = "FAILURE"
        details = stderr or stdout or "Non-zero return code"

    else:
        status = "FAILURE"
        details = stdout or "Ambiguous exploit output"

    return {
        "status": status,
        "details": details,
        "artifact": {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": result.returncode,
        },
    }


@app.post("/execute/trigger_bind_shell")
def execute_trigger_bind_shell(payload: Dict[str, Any]):
    try:
        params = payload["parameters"]
        executor = TriggerBindShellExecutor(
            host=params["host"],
            service_protocol=params["service_protocol"],
            service_port=params["service_port"],
            dialogue=params["dialogue"],
            close_channel=params["close_channel"],
            bind_port=params["bind_port"],
        )

        return executor.execute()

    except Exception as e:
        logger.exception("[EXECUTOR] trigger_bind_shell failed")
        return {"status": "EXECUTOR_ERROR", "details": str(e)}


@app.post("/execute/trigger_reverse_shell")
def execute_trigger_reverse_shell(payload: Dict[str, Any]):
    try:
        logger.info(f"[REVERSE_SHELL] Payload: {payload}")
        params = payload["parameters"]
        executor = TriggerReverseShellExecutor(
            host=params["host"],
            service_protocol=params["service_protocol"],
            service_port=params["service_port"],
            dialogue=params["dialogue"],
            callback_port=params["callback_port"],
        )

        return executor.execute()

    except Exception as e:
        logger.exception("[EXECUTOR] trigger_reverse_shell failed")
        return {"status": "EXECUTOR_ERROR", "details": str(e)}


@app.post("/execute/http_rce_single_request")
def execute_http_rce_single_request(payload: Dict[str, Any]):
    try:
        logger.info(f"[HTTP_RCE_SINGLE] Payload: {payload}")
        params = payload["parameters"]
        executor = HttpRceSingleRequestExecutor(
            host=params["host"],
            scheme=params["scheme"],
            port=params["port"],
            method=params["method"],
            path=params["path"],
            query=params["query"],
            success_regex=params["success_regex"],
        )

        return executor.execute()

    except Exception as e:
        logger.exception("[EXECUTOR] http_rce_single_request failed")
        return {"status": "EXECUTOR_ERROR", "details": str(e)}


@app.post("/execute/credential_bruteforce")
def execute_credential_bruteforce(payload: Dict[str, Any]):
    try:
        logger.info(f"[CREDENTIAL_BRUTEFORCE] Payload: {payload}")
        params = payload.get("parameters")

        if not params:
            return {
                "status": "EXECUTOR_ERROR",
                "details": "Missing parameters for credential_bruteforce",
            }

        return bruteforce_execute(params)

    except Exception as e:
        logger.exception("[EXECUTOR] credential_bruteforce failed")
        return {
            "status": "EXECUTOR_ERROR",
            "details": str(e),
        }


@app.post("/execute/framework_module_execution")
def execute_framework_module_execution(payload: Dict[str, Any]):
    try:
        logger.info(f"[FRAMEWORK_MODULE_EXECUTION] Payload: {payload}")
        params = payload.get("parameters")

        if not params:
            return {
                "status": "EXECUTOR_ERROR",
                "details": "Missing parameters for framework_module_execution",
            }

        return framework_module_execute(params)

    except Exception as e:
        logger.exception("[EXECUTOR] framework_module_execution failed")
        return {
            "status": "EXECUTOR_ERROR",
            "details": str(e),
        }


@app.post("/framework_module_search")
def framework_module_search(payload: Dict[str, Any]):
    try:
        logger.info(f"[FRAMEWORK_MODULE_SEARCH] Payload: {payload}")
        cve = payload.get("cve")
        if not cve:
            return {"ok": False, "error": "Missing CVE"}

        return framework_module_search_execute(cve)

    except Exception as e:
        logger.exception(f"[FRAMEWORK_SEARCH] failed: {e}")
        return {"ok": False, "error": str(e)}


@app.post("/execute/framework_module_install")
def framework_module_install(payload: dict):
    logger.info(f"[FRAMEWORK_MODULE_INSTALL] Payload: {payload}")
    kali_path = payload.get("parameters", {}).get("path")

    if not os.path.exists(kali_path):
        return {
            "status": "FAILURE",
            "details": f"Kali exploit file not found: {kali_path}",
        }

    logger.warning("[DEBUG] framework_module_install CALLED")
    logger.warning(f"[DEBUG] kali_path = {kali_path}")
    logger.warning(f"[DEBUG] exists(kali_path) = {os.path.exists(kali_path)}")

    try:
        target_path = build_msf_module_path(kali_path)
        logger.warning(f"[DEBUG] COPY {kali_path} -> {target_path}")
        if os.path.exists(target_path):
            return {
                "status": "SUCCESS",
                "details": "Framework module already copied",
            }

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        shutil.copyfile(kali_path, target_path)

        reload_proc = subprocess.run(
            'msfconsole -q -x "reload_all; exit"',
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if reload_proc.returncode != 0:
            return {
                "status": "FAILURE",
                "details": reload_proc.stderr
                or reload_proc.stdout
                or "Metasploit reload_all failed",
            }
        logger.info(f"[FRAMEWORK_MODULE_INSTALL] success for {kali_path}")
        return {
            "status": "SUCCESS",
            "details": "Framework module installed",
        }

    except Exception as e:
        logger.exception(f"[FRAMEWORK_MODULE_INSTALL] failed for {kali_path}")
        return {"status": "FAILURE", "details": str(e)}


@app.post("/execute/curl")
def execute_curl(payload: Dict[str, Any]):
    """
    Execute a curl request from the Kali Engine.
    Used for generic HTTP probing (OpenAPI, headers, pages, etc).
    """
    try:
        url = payload.get("url")
        method = payload.get("method", "GET").upper()
        headers = payload.get("headers", {})
        data = payload.get("data")
        follow_redirects = payload.get("follow_redirects", True)
        include_headers = payload.get("include_headers", False)

        if not url:
            return {
                "status": "EXECUTOR_ERROR",
                "details": "Missing 'url' parameter",
            }

        if not url.startswith(("http://", "https://")):
            return {
                "status": "EXECUTOR_ERROR",
                "details": "Only http:// or https:// URLs are allowed",
            }

        # Command creation
        cmd = ["curl", "-sS"]
        if follow_redirects:
            cmd.append("-L")
        if include_headers:
            cmd.append("-i")
        cmd.extend(["-X", method])
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        if data:
            cmd.extend(["--data", data])
        cmd.append(url)

        logger.info(f"[CURL_EXECUTOR] Command: {cmd}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=HTTP_TIMEOUT,
        )

        return {
            "status": "SUCCESS" if result.returncode == 0 else "FAILURE",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "command": " ".join(cmd),
        }

    except subprocess.TimeoutExpired:
        logger.exception("[CURL_EXECUTOR] timeout")
        return {
            "status": "EXECUTOR_ERROR",
            "details": "curl execution timed out",
        }

    except Exception as e:
        logger.exception("[CURL_EXECUTOR] failed")
        return {
            "status": "EXECUTOR_ERROR",
            "details": str(e),
        }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.patch("/update_exploit")
def update_exploit(req: FileUpdateRequest):
    script = base64.b64decode(req.content_b64).decode("utf-8")
    with open(req.path, "w", encoding="utf-8") as f:
        f.write(script)
    return {"status": "ok"}
