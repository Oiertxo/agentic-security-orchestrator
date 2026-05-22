from typing import Any, Dict, Optional

import httpx
from langfuse import observe

from src.state import PlannerOutput
from src.utils.utils import get_engine_url


def _normalize_cve_lookup_payload(
    *,
    args: Optional[Dict[str, Any]] = None,
    plan: PlannerOutput,
) -> Dict[str, Any]:
    """
    Normalizes either:
      - args={product, version, service, vendor, ostype, extrainfo, port, resultsPerPage, maxResults}
      - plan={"next_tool":"cve_lookup", "arguments":{...}}
    into the /cve_lookup request schema.

    Raises ValueError if required fields are missing.
    """
    if plan is not None:
        next_tool = plan.get("next_tool")
        if next_tool != "cve_lookup":
            raise ValueError(
                f"CVE executor only supports next_tool='cve_lookup' for MVP, got: {next_tool}"
            )
        arguments = plan.get("arguments", {})
    else:
        arguments = args or {}

    product = arguments.get("product")
    if not product or not isinstance(product, str):
        raise ValueError("Missing required 'product' (string) for cve_lookup.")

    payload: Dict[str, Any] = {
        "name": arguments.get("name", ""),
        "product": product,
        "version": arguments.get("version"),
        "app_name": arguments.get("app_name"),
        "app_version": arguments.get("app_version"),
        "service": arguments.get("service"),
        "vendor": arguments.get("vendor"),
        "ostype": arguments.get("ostype"),
        "extrainfo": arguments.get("extrainfo"),
        "port": arguments.get("port"),
    }

    port = payload.get("port")
    if port is not None:
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                raise ValueError
            payload["port"] = port_int
        except Exception:
            raise ValueError("'port' must be an int between 1 and 65535.")

    payload = {k: v for k, v in payload.items() if v is not None}
    return payload


@observe(name="CVE executor client")
async def call_cve_lookup(
    *,
    args: Optional[Dict[str, Any]] = None,
    plan: PlannerOutput,
    base_url: Optional[str] = None,
    timeout: float = 120.0,
) -> Dict[str, Any]:

    payload = _normalize_cve_lookup_payload(args=args, plan=plan)
    base = (base_url or get_engine_url()).rstrip("/")
    url = f"{base}/cve_lookup"

    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        try:
            resp = await client.post(
                url, json=payload, headers={"Content-Type": "application/json"}
            )

            try:
                data = resp.json()
            except Exception:
                data = {}

            return {
                "ok": resp.status_code < 400,
                "status_code": resp.status_code,
                "request": payload,
                "response": data,
                "error": None if resp.status_code < 400 else data.get("detail"),
            }

        except httpx.ReadTimeout:
            return {
                "ok": False,
                "status_code": "timeout",
                "request": payload,
                "response": None,
                "error": "Client timeout waiting for CVE lookup",
            }

        except httpx.HTTPError as e:
            return {
                "ok": False,
                "status_code": None,
                "request": payload,
                "response": None,
                "error": str(e),
            }
