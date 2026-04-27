import asyncio
from typing import Any, Dict, Optional

import httpx
from langfuse import observe

from src.logger import logger
from src.utils.utils import get_engine_url


def _normalize_search_exploit_payload(
    *, args: Optional[Dict[str, Any]] = None, plan: Optional[Dict[str, Any]] = None
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
async def call_search_exploit(
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

    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        for attempt in range(retries + 1):
            try:
                resp = await client.post(
                    url, json=payload, headers={"Content-Type": "application/json"}
                )
                try:
                    data = resp.json()
                except Exception:
                    data = {}

                if isinstance(data, dict):
                    count = data.get("count", 0)
                    query_type = "CVE" if payload.get("cve") else "Product"
                    logger.info(
                        f"[VULN_MAP_EXECUTOR_CLIENT] Searchsploit ok={resp.status_code < 400} type={query_type} results={count}"
                    )

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
                    "error": (
                        data.get("detail")
                        if isinstance(data, dict) and "detail" in data
                        else f"HTTP {resp.status_code}"
                    ),
                }

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPError) as e:
                last_exc = e
                if attempt == retries:
                    break
                sleep_s = backoff_base * (2**attempt)
                logger.warning(
                    f"[VULN_MAP_EXECUTOR_CLIENT] Retrying vulnerability mapping in {sleep_s}s... (Attempt {attempt + 1}/{retries})"
                )
                await asyncio.sleep(sleep_s)
                attempt += 1

    return {
        "ok": False,
        "status_code": None,
        "request": payload,
        "response": None,
        "error": str(last_exc) if last_exc else "Unknown transport error",
    }


@observe(name="Vuln Map executor client - framework search")
async def call_search_framework_modules(
    *,
    cve: str,
    base_url: Optional[str] = None,
    timeout: float = 30.0,
    retries: int = 2,
    backoff_base: float = 0.5,
) -> Dict[str, Any]:
    """
    Calls the engine /framework_module_search endpoint.
    Searches Metasploit modules for a given CVE.
    """

    payload = {"cve": cve}
    logger.info(f"[VULN_MAP_EXECUTOR_CLIENT] Metasploit search for CVE {cve}")

    base = (base_url or get_engine_url()).rstrip("/")
    url = f"{base}/framework_module_search"

    last_exc: Optional[Exception] = None

    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        for attempt in range(retries + 1):
            try:
                resp = await client.post(
                    url, json=payload, headers={"Content-Type": "application/json"}
                )

                try:
                    data = resp.json()
                except Exception:
                    data = {}

                if resp.status_code < 400:
                    modules = data.get("modules", [])
                    logger.info(
                        f"[VULN_MAP_EXECUTOR_CLIENT] Metasploit modules found={len(modules)}"
                    )
                    return {
                        "ok": True,
                        "status_code": resp.status_code,
                        "request": payload,
                        "modules": modules,
                        "error": None,
                    }

                return {
                    "ok": False,
                    "status_code": resp.status_code,
                    "request": payload,
                    "modules": [],
                    "error": (
                        data.get("detail")
                        if isinstance(data, dict) and "detail" in data
                        else f"HTTP {resp.status_code}"
                    ),
                }

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPError) as e:
                last_exc = e
                if attempt == retries:
                    break
                sleep_s = backoff_base * (2**attempt)
                logger.warning(
                    f"[VULN_MAP_EXECUTOR_CLIENT] Retrying framework search in {sleep_s}s "
                    f"(Attempt {attempt + 1}/{retries})"
                )
                await asyncio.sleep(sleep_s)

    return {
        "ok": False,
        "status_code": None,
        "request": payload,
        "modules": [],
        "error": str(last_exc) if last_exc else "Unknown transport error",
    }
