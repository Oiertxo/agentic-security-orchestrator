import time, httpx
from src.utils.utils import get_engine_url
from typing import Optional, Dict, Any
from src.logger import logger
from langfuse import observe

def _normalize_search_exploit_payload(
    *, 
    args: Optional[Dict[str, Any]] = None, 
    plan: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Extracts search terms from LLM arguments or the current plan.
    Prioritizes explicit CVE, then falls back to product/version.
    """
    args = args or {}
    plan = plan or {}
    llm_args = plan.get("arguments", {})    
    combined = {**plan, **llm_args, **args}

    return {
        "cve": combined.get("cve"),
        "product": combined.get("product"),
        "version": combined.get("version"),
    }

@observe(name="Vuln Map executor client")
def call_search_exploit(
    *,
    args: Optional[Dict[str, Any]] = None,
    plan: Optional[Dict[str, Any]] = None,
    base_url: Optional[str] = None,
    timeout: float = 30.0,
    retries: int = 2,
    backoff_base: float = 0.5,
) -> Dict[str, Any]:
    """
    Calls the engine /search_exploit endpoint.
    Supports searching by CVE or Product/Version.
    """
    payload = _normalize_search_exploit_payload(args=args, plan=plan)
    logger.info(f"[VULN_MAP_EXECUTOR_CLIENT] Searchsploit arguments: {payload}")

    base = (base_url or get_engine_url()).rstrip("/")
    url = f"{base}/search_exploit"

    last_exc: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(
                    url, 
                    json=payload, 
                    headers={"Content-Type": "application/json"}
                )

            data = None
            try:
                data = resp.json()
            except Exception:
                data = None

            if isinstance(data, dict):
                count = data.get("count", 0)
                query_type = "CVE" if payload.get("cve") else "Product"
                logger.info(f"[VULN_MAP_EXECUTOR_CLIENT] Searchsploit ok={resp.status_code<400} type={query_type} results={count}")

            if resp.status_code < 400:
                return {
                    "ok": True,
                    "status_code": resp.status_code,
                    "request": payload,
                    "response": data,
                    "error": None,
                }

            return {
                "ok": False,
                "status_code": resp.status_code,
                "request": payload,
                "response": data,
                "error": (data.get("detail") if isinstance(data, dict) and "detail" in data
                          else f"HTTP {resp.status_code}"),
            }

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPError) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff_base * (2 ** attempt))
                continue

    return {
        "ok": False,
        "status_code": None,
        "request": payload,
        "response": None,
        "error": str(last_exc) if last_exc else "Unknown transport error",
    }