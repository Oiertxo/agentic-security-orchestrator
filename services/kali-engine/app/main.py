import base64
import json
import logging
import os
import shutil
import subprocess
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
    HTTP_TIMEOUT,
    MAX_TOTAL_RESULTS,
    NVD_BASE_URL,
    CveLookupRequest,
    ExploitRequest,
    FileUpdateRequest,
    ReconRequest,
    SearchsploitRequest,
    _build_keyword_search,
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
            logger.info(
                f"CVE_LOOKUP: {NVD_BASE_URL}, {_nvd_headers()}, {params}, {HTTP_TIMEOUT}"
            )
            r = requests.get(
                NVD_BASE_URL,
                headers=_nvd_headers(),
                params=params,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise HTTPException(status_code=502, detail=f"NVD request failed: {e}")

        if r.status_code != 200:
            raise HTTPException(
                status_code=502, detail=f"NVD returned {r.status_code}: {r.text[:300]}"
            )

        data = r.json()
        vulns = data.get("vulnerabilities", [])
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
        "note": "Summarized CVE records from NVD CVE API v2.0 (keyword search + pagination).",
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

    if result.returncode != 0:
        return {
            "status": "FAILURE",
            "details": result.stderr.strip() or result.stdout.strip(),
            "artifact": {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            },
        }

    return {
        "status": "SUCCESS",
        "details": result.stdout.strip() or "Command executed successfully",
        "artifact": {
            "stdout": result.stdout,
            "stderr": result.stderr,
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.patch("/update_exploit")
def update_exploit(req: FileUpdateRequest):
    script = base64.b64decode(req.content_b64).decode("utf-8")
    with open(req.path, "w", encoding="utf-8") as f:
        f.write(script)
    return {"status": "ok"}
